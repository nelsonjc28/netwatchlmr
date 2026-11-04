import asyncio
import ipaddress
import json
import os
import re
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

import jwt
import requests
from fastapi import FastAPI, HTTPException, Request, Response, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from passlib.context import CryptContext
from pydantic import BaseModel

from backend.database import DeviceInfo, SessionLocal, User, init_db
from backend.scanner import load_config, ping_details, port_scan, scan_open_tcp_ports
from backend.topology import build_network_snapshot, render_alert_message
from backend.topology_detector import build_parent_mac_edges

APP_ROOT = Path(__file__).resolve().parents[1]
FRONTEND_DIR = APP_ROOT / "frontend"
CONFIG_PATH = APP_ROOT / "config.json"
DB_SECRET_KEY = os.getenv("NETWATCH_SECRET_KEY", "netwatch-dev-secret-change-me")
ALGORITHM = "HS256"
ACCESS_TOKEN_TTL = timedelta(hours=8)

app = FastAPI(title="NetWatch LMR", version="1.0.0")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.mount("/static", StaticFiles(directory=str(FRONTEND_DIR)), name="static")

STATE: Dict[str, Any] = {
    "snapshot": {},
    "clients": [],
    "last_alerts": {},
    "monitor_task": None,
}

pwd_context = CryptContext(schemes=["pbkdf2_sha256"], deprecated="auto")


class LoginRequest(BaseModel):
    username: str
    password: str


class DeviceUpdateRequest(BaseModel):
    custom_name: Optional[str] = None
    area: Optional[str] = None
    admin_user: Optional[str] = None
    admin_pass: Optional[str] = None
    ip: Optional[str] = None
    parent_mac: Optional[str] = None


def normalize_mac(value: Optional[str]) -> Optional[str]:
    if value is None:
        return None
    cleaned = str(value).strip().upper().replace("-", ":").replace(" ", "")
    if not cleaned:
        return None
    if len(cleaned) == 12 and re.fullmatch(r"[0-9A-F]{12}", cleaned):
        cleaned = ":".join(cleaned[i : i + 2] for i in range(0, 12, 2))
    elif len(cleaned) != 17 or not re.fullmatch(r"(?:[0-9A-F]{2}:){5}[0-9A-F]{2}", cleaned):
        return None
    return cleaned if len(cleaned) == 17 else None


def create_default_user() -> None:
    with SessionLocal() as session:
        user = session.query(User).filter_by(username="admin").first()
        if user is None:
            session.add(User(username="admin", hashed_password=pwd_context.hash("admin123")))
            session.commit()


init_db()
create_default_user()


def create_access_token(username: str) -> str:
    payload = {
        "sub": username,
        "exp": datetime.now(timezone.utc) + ACCESS_TOKEN_TTL,
    }
    return jwt.encode(payload, DB_SECRET_KEY, algorithm=ALGORITHM)


def verify_access_token(token: Optional[str]) -> Optional[str]:
    if not token:
        return None
    try:
        payload = jwt.decode(token, DB_SECRET_KEY, algorithms=[ALGORITHM])
        username = payload.get("sub")
        return username if isinstance(username, str) else None
    except (jwt.PyJWTError, TypeError, ValueError):
        return None


def require_auth(request: Request) -> str:
    token = request.cookies.get("access_token")
    username = verify_access_token(token)
    if not username:
        raise HTTPException(status_code=401, detail="Unauthorized")
    return username


async def emit_to_clients(payload: Dict[str, Any]) -> None:
    clients = list(STATE["clients"])
    for ws in clients:
        try:
            await ws.send_json(payload)
        except Exception:
            if ws in STATE["clients"]:
                STATE["clients"].remove(ws)


def send_telegram_alert(message: str) -> None:
    """Send a Telegram notification only when the config enables it."""
    config = load_config()
    telegram_cfg = config.get("telegram", {})
    if not telegram_cfg.get("enabled", False):
        return
    bot_token = telegram_cfg.get("bot_token", "")
    chat_id = telegram_cfg.get("chat_id", "")
    if not bot_token or not chat_id:
        return

    try:
        response = requests.post(
            f"https://api.telegram.org/bot{bot_token}/sendMessage",
            json={"chat_id": chat_id, "text": message, "parse_mode": "HTML"},
            timeout=5,
        )
        response.raise_for_status()
    except requests.RequestException:
        return


def send_webhook_alert(message: str) -> None:
    """Optional outgoing webhook for campus notification services."""
    config = load_config()
    telegram_cfg = config.get("telegram", {})
    webhook_url = telegram_cfg.get("webhook_url", "")
    if not webhook_url:
        return
    try:
        requests.post(webhook_url, json={"message": message}, timeout=5)
    except requests.RequestException:
        return


def evaluate_alerts(snapshot: Dict[str, Any]) -> None:
    """Deduplicate alerts to avoid spam and emit state-change notifications."""
    config = load_config()
    cooldown = config.get("alert_policy", {}).get("cooldown_seconds", 180)
    latest = STATE["last_alerts"]

    for node in snapshot.get("root_causes", []):
        key = f"{node['ip']}|{node['status']}"
        last_status = latest.get(key)
        now = asyncio.get_running_loop().time()
        if last_status and (now - last_status) < cooldown:
            continue

        message = f"{node['name']} ({node['ip']}) - {node['department']} - {node['reason']}"
        send_telegram_alert(message)
        send_webhook_alert(message)
        latest[key] = now

    for node in snapshot.get("nodes", []):
        ip = node["ip"]
        status = node["status"]
        key = f"{ip}|{status}"
        if key not in latest:
            latest[key] = asyncio.get_running_loop().time()
            message = render_alert_message(node, status, None)
            if message:
                send_telegram_alert(message)
                send_webhook_alert(message)


async def refresh_snapshot() -> Dict[str, Any]:
    """Collect fresh scan data and return a snapshot for clients."""
    try:
        snapshot = build_network_snapshot()
    except Exception:
        snapshot = {
            "timestamp": "unavailable",
            "campus": "NetWatch LMR",
            "nodes": [],
            "edges": [],
            "root_causes": [],
            "summary": {
                "total": 0,
                "operational": 0,
                "down": 0,
                "warnings": 0,
                "conflicts": 0,
                "suppressed": 0,
            },
            "alerts": {
                "conflict_ips": [],
                "status_map": {},
            },
        }

    STATE["snapshot"] = snapshot
    evaluate_alerts(snapshot)
    return snapshot


def attach_db_metadata(nodes: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    with SessionLocal() as session:
        records = session.query(DeviceInfo).all()
    db_by_mac = {normalize_mac(record.mac): record for record in records if normalize_mac(record.mac)}

    merged: List[Dict[str, Any]] = []
    for node in nodes:
        item = dict(node)
        mac = normalize_mac(item.get("mac")) or normalize_mac(item.get("id"))
        record = db_by_mac.get(mac) if mac else None
        if record is not None:
            item["mac"] = record.mac
            # The IP in the current scan is authoritative; the saved IP is only a fallback.
            item["ip"] = item.get("ip") or record.ip
            item["custom_name"] = record.custom_name or item.get("name")
            item["area"] = record.area or item.get("department", "Sin Asignar")
            item["admin_user"] = record.admin_user
            item["admin_pass"] = record.admin_pass
            item["parent_mac"] = normalize_mac(record.parent_mac)
            item["pos_x"] = record.pos_x
            item["pos_y"] = record.pos_y
            item["label"] = f"{item['area']}\n{item['custom_name'] or item.get('name', 'Dispositivo')}\n{item.get('ip', 'Sin IP')}"
            item["title"] = item.get("title") or item.get("department", "Sin Asignar")
        else:
            item["custom_name"] = item.get("name")
            item["area"] = item.get("department", "Sin Asignar")
            item["mac"] = mac or item.get("mac") or item.get("id")
            item["label"] = f"{item['area']}\n{item.get('name', 'Dispositivo')}\n{item.get('ip', 'Sin IP')}"
        merged.append(item)
    return merged


def build_filtered_status_snapshot(snapshot: Dict[str, Any]) -> Dict[str, Any]:
    nodes = attach_db_metadata(snapshot.get("nodes", []))
    online_nodes = [node for node in nodes if str(node.get("status", "")).lower() not in {"down", "inaccessible_due_to_parent", "unknown"}]

    mac_counts: Dict[str, int] = {}
    for node in online_nodes:
        mac = normalize_mac(node.get("mac"))
        if mac:
            mac_counts[mac] = mac_counts.get(mac, 0) + 1

    node_id_by_address: Dict[str, str] = {}
    for node in online_nodes:
        scan_id = str(node.get("id") or node.get("ip"))
        mac = normalize_mac(node.get("mac"))
        # MAC is the stable Vis.js identity when unique in this scan. If a
        # bridged network reports the same MAC for multiple IPs, use the IP.
        node_id = mac if mac and mac_counts[mac] == 1 else scan_id
        node["scan_id"] = scan_id
        node["id"] = node_id
        node["vis_id"] = node_id
        for address in (scan_id, node.get("ip"), node.get("mac")):
            if address:
                normalized_address = normalize_mac(str(address)) or str(address)
                node_id_by_address[normalized_address] = node_id

    # Resolve scan-time IP edges, then replace a child's inferred parent with
    # the explicitly saved parent MAC when available.
    edges_by_pair: Dict[tuple[str, str], Dict[str, Any]] = {}
    children_with_saved_parent = {
        str(node.get("id")) for node in online_nodes if normalize_mac(node.get("parent_mac"))
    }
    for edge in snapshot.get("edges", []):
        source_address = str(edge.get("from"))
        target_address = str(edge.get("to"))
        source_id = node_id_by_address.get(normalize_mac(source_address) or source_address)
        target_id = node_id_by_address.get(normalize_mac(target_address) or target_address)
        if source_id is None or target_id is None:
            continue
        if target_id in children_with_saved_parent:
            continue
        edges_by_pair[(source_id, target_id)] = {**edge, "from": source_id, "to": target_id}

    for edge in build_parent_mac_edges(online_nodes):
        edges_by_pair[(str(edge["from"]), str(edge["to"]))] = edge

    edges = list(edges_by_pair.values())

    online_ids = set(node_id_by_address)
    root_causes = [
        cause
        for cause in snapshot.get("root_causes", [])
        if str(cause.get("ip")) in online_ids
    ]
    summary = {
        "total": len(online_nodes),
        "operational": sum(1 for node in online_nodes if node.get("status") == "operational"),
        "down": sum(1 for node in online_nodes if node.get("status") == "down"),
        "warnings": sum(1 for node in online_nodes if node.get("status") == "warning"),
        "conflicts": sum(1 for node in online_nodes if node.get("status") == "conflict"),
        "suppressed": sum(1 for node in online_nodes if node.get("status") == "inaccessible_due_to_parent"),
    }
    return {
        **snapshot,
        "nodes": online_nodes,
        "edges": edges,
        "root_causes": root_causes,
        "summary": summary,
        "alerts": {
            "conflict_ips": snapshot.get("alerts", {}).get("conflict_ips", []),
            "status_map": {str(node.get("vis_id") or node.get("ip") or node.get("id")): node.get("status") for node in online_nodes},
        },
    }


@app.get("/health")
async def health() -> Dict[str, str]:
    return {"status": "ok", "service": "NetWatch LMR"}


@app.get("/api/status")
async def get_status(response: Response, request: Request) -> Dict[str, Any]:
    require_auth(request)
    response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate"
    response.headers["Pragma"] = "no-cache"
    snapshot = await refresh_snapshot()
    return build_filtered_status_snapshot(snapshot)


@app.get("/api/topology")
async def get_topology(response: Response, request: Request) -> Dict[str, Any]:
    require_auth(request)
    response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate"
    response.headers["Pragma"] = "no-cache"
    snapshot = await refresh_snapshot()
    return build_filtered_status_snapshot(snapshot)


@app.get("/api/devices/{value}")
async def get_device_details(value: str, request: Request) -> Dict[str, Any]:
    """Return diagnostics by IP or persisted record metadata by MAC."""
    require_auth(request)

    normalized_mac = normalize_mac(value)
    if normalized_mac:
        with SessionLocal() as session:
            device = session.get(DeviceInfo, normalized_mac)
            if device is None:
                raise HTTPException(status_code=404, detail="Dispositivo no encontrado")
            return {
                "mac": device.mac,
                "ip": device.ip,
                "custom_name": device.custom_name,
                "area": device.area,
                "admin_user": device.admin_user,
                "admin_pass": device.admin_pass,
                "parent_mac": device.parent_mac,
                "pos_x": device.pos_x,
                "pos_y": device.pos_y,
            }

    try:
        normalized_ip = str(ipaddress.ip_address(value))
    except ValueError as error:
        raise HTTPException(status_code=400, detail="Dirección IP o MAC inválida") from error

    node = next((item for item in STATE["snapshot"].get("nodes", []) if item.get("ip") == normalized_ip), None)
    if node is None:
        raise HTTPException(status_code=404, detail="El dispositivo no está en el último escaneo")

    ping = ping_details(normalized_ip)
    open_ports = scan_open_tcp_ports(normalized_ip)
    port_services = {
        22: "SSH",
        53: "DNS",
        80: "HTTP",
        443: "HTTPS",
        445: "SMB",
        548: "AFP",
        631: "IPP / impresión",
        3389: "RDP",
        5000: "Servicio web",
        8080: "HTTP alternativo",
        8443: "HTTPS alternativo",
    }
    return {
        "device": node,
        "diagnostics": {
            **ping,
            "tcp_ports_scanned": list(port_services.keys()),
            "open_tcp_ports": [
                {"port": port, "service": port_services.get(port, "Servicio TCP")}
                for port in open_ports
            ],
            "scanned_at": datetime.now(timezone.utc).isoformat(),
            "limitations": [
                "Los puertos listados son servicios TCP comunes; no representan todos los servicios del equipo.",
                "El tipo de dispositivo y fabricante pueden ser inferidos; una MAC privada/aleatoria puede ocultar el fabricante.",
                "El sistema operativo, modelo exacto y conexiones físicas no se pueden confirmar solo con IP/MAC.",
            ],
        },
    }


@app.post("/api/devices/{value}/update")
async def update_db_device(value: str, payload: DeviceUpdateRequest, request: Request) -> Dict[str, Any]:
    require_auth(request)
    normalized = normalize_mac(value)
    if not normalized:
        raise HTTPException(status_code=400, detail="MAC inválida")

    with SessionLocal() as session:
        device = session.get(DeviceInfo, normalized)
        if device is None:
            device = DeviceInfo(mac=normalized)
            session.add(device)

        for field in ("custom_name", "area", "admin_user", "admin_pass", "ip"):
            value_data = getattr(payload, field)
            if value_data is not None:
                setattr(device, field, value_data.strip() if isinstance(value_data, str) else value_data)

        if payload.parent_mac is not None:
            parent_mac = normalize_mac(payload.parent_mac)
            if payload.parent_mac.strip() and parent_mac is None:
                raise HTTPException(status_code=400, detail="MAC padre inválida")
            if parent_mac == normalized:
                raise HTTPException(status_code=400, detail="Un dispositivo no puede ser su propio padre")
            if parent_mac:
                parent_by_mac = {
                    normalize_mac(mac): normalize_mac(saved_parent)
                    for mac, saved_parent in session.query(DeviceInfo.mac, DeviceInfo.parent_mac).all()
                    if normalize_mac(mac) and normalize_mac(saved_parent)
                }
                parent_by_mac[normalized] = parent_mac
                ancestor = parent_mac
                visited = set()
                while ancestor and ancestor not in visited:
                    if ancestor == normalized:
                        raise HTTPException(status_code=400, detail="La jerarquía no puede contener ciclos")
                    visited.add(ancestor)
                    ancestor = parent_by_mac.get(ancestor)
            device.parent_mac = parent_mac

        session.commit()
        session.refresh(device)

    return {
        "status": "ok",
        "device": {
            "mac": device.mac,
            "ip": device.ip,
            "custom_name": device.custom_name,
            "area": device.area,
            "admin_user": device.admin_user,
            "admin_pass": device.admin_pass,
            "parent_mac": device.parent_mac,
        },
    }


@app.post("/api/layout/save")
async def save_layout(payload: Dict[str, Dict[str, float]], request: Request) -> Dict[str, Any]:
    require_auth(request)
    saved = 0
    with SessionLocal() as session:
        for raw_mac, coords in payload.items():
            normalized = normalize_mac(raw_mac)
            if not normalized or not isinstance(coords, dict):
                continue
            device = session.get(DeviceInfo, normalized)
            if device is None:
                device = DeviceInfo(mac=normalized)
                session.add(device)
            try:
                device.pos_x = float(coords.get("x"))
                device.pos_y = float(coords.get("y"))
            except (TypeError, ValueError):
                continue
            saved += 1
        session.commit()
    return {"status": "ok", "saved": saved}


@app.post("/api/login")
async def login(payload: LoginRequest, response: Response) -> Dict[str, Any]:
    with SessionLocal() as session:
        user = session.query(User).filter_by(username=payload.username).first()
    if user is None or not pwd_context.verify(payload.password, user.hashed_password):
        raise HTTPException(status_code=401, detail="Credenciales inválidas")

    token = create_access_token(payload.username)
    response.set_cookie(
        key="access_token",
        value=token,
        httponly=True,
        samesite="lax",
        secure=False,
        path="/",
        max_age=int(ACCESS_TOKEN_TTL.total_seconds()),
    )
    return {"status": "ok", "user": {"username": payload.username}}


@app.post("/api/logout")
async def logout(response: Response) -> Dict[str, str]:
    response.delete_cookie(key="access_token", path="/")
    return {"status": "ok"}


@app.get("/", response_class=HTMLResponse)
async def index():
    with (FRONTEND_DIR / "index.html").open("r", encoding="utf-8") as file:
        return HTMLResponse(
            content=file.read(),
            media_type="text/html",
            headers={"Content-Type": "text/html; charset=utf-8", "Cache-Control": "no-store, no-cache, must-revalidate", "Pragma": "no-cache"},
        )


@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    await websocket.accept()
    token = websocket.cookies.get("access_token")
    if not verify_access_token(token):
        await websocket.close(code=1008, reason="Unauthorized")
        return

    STATE["clients"].append(websocket)
    try:
        if STATE["snapshot"]:
            await websocket.send_json(build_filtered_status_snapshot(STATE["snapshot"]))
        else:
            await websocket.send_json(build_filtered_status_snapshot(await refresh_snapshot()))

        monitor_task = STATE.get("monitor_task")
        if monitor_task is None or monitor_task.done():
            STATE["monitor_task"] = asyncio.create_task(background_monitor())

        while True:
            try:
                await asyncio.wait_for(websocket.receive_text(), timeout=1)
            except asyncio.TimeoutError:
                continue
    except WebSocketDisconnect:
        if websocket in STATE["clients"]:
            STATE["clients"].remove(websocket)


async def background_monitor():
    """Refresh and broadcast only while an authenticated WebSocket is connected."""
    while STATE["clients"]:
        await refresh_snapshot()
        await emit_to_clients(build_filtered_status_snapshot(STATE["snapshot"]))
        await asyncio.sleep(5)


@app.on_event("startup")
async def startup_event() -> None:
    init_db()
    create_default_user()


if __name__ == "__main__":
    import uvicorn

    uvicorn.run("backend.main:app", host="0.0.0.0", port=8000, reload=False)
