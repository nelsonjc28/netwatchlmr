from __future__ import annotations

import ipaddress
import json
import re
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from typing import Any, Dict, Iterable, List, Optional

from backend.scanner import discover_network_devices, get_local_network_info, load_config, ping_host, port_scan, resolve_hostname


MAC_VENDOR_PREFIXES = {
    "00:03:93": "Apple", "00:0A:95": "Apple", "00:17:F2": "Apple", "00:1B:63": "Apple",
    "00:1E:C2": "Apple", "00:21:E9": "Apple", "00:23:12": "Apple", "00:25:00": "Apple",
    "3C:07:54": "Apple", "AC:BC:32": "Apple", "C8:3A:35": "Apple", "F0:18:98": "Apple",
    "00:16:32": "Samsung", "5C:0A:5B": "Samsung", "8C:77:12": "Samsung", "A8:06:00": "Samsung",
    "00:1A:11": "Google", "F4:F5:D8": "Google", "64:09:80": "Xiaomi", "78:11:DC": "Xiaomi",
    "00:1B:54": "Cisco", "00:1E:49": "Cisco", "00:1F:CA": "Cisco", "00:25:84": "Cisco",
    "00:15:6D": "Ubiquiti", "24:A4:3C": "Ubiquiti", "68:72:51": "Ubiquiti", "74:83:C2": "Ubiquiti",
    "00:1D:0F": "TP-Link", "14:CC:20": "TP-Link", "50:C7:BF": "TP-Link", "EC:08:6B": "TP-Link",
    "00:1B:21": "Intel", "3C:52:82": "Intel", "F8:16:54": "Intel",
}

DEVICE_TYPE_LABELS = {
    "Router": "Router", "Switch": "Switch", "Access Point": "Punto de acceso",
    "Computer": "Computadora", "Smartphone": "Teléfono", "Tablet": "Tablet",
    "Printer": "Impresora", "Server": "Servidor", "Unknown": "Dispositivo no identificado",
}


def identify_device(ip: str, node: Dict[str, Any], gateway_ip: Optional[str], local_ips: List[str], hostname: Optional[str]) -> Dict[str, str]:
    """Infer a device category from explicit inventory, name and MAC vendor hints."""
    mac = node.get("mac")
    vendor = MAC_VENDOR_PREFIXES.get(str(mac or "").upper()[:8], "Desconocido")
    configured_type = str(node.get("type", "")).strip().lower()
    configured_types = {
        "core": "Router", "router": "Router", "switch": "Switch", "ap": "Access Point",
        "access point": "Access Point", "pc": "Computer", "computer": "Computer",
        "móvil": "Smartphone", "movil": "Smartphone", "mobile": "Smartphone", "phone": "Smartphone",
        "tablet": "Tablet", "servidor": "Server", "server": "Server", "printer": "Printer",
    }
    if ip == gateway_ip:
        device_type, method, confidence = "Router", "Puerta de enlace del sistema", "high"
    elif ip in local_ips:
        device_type, method, confidence = "Computer", "Host local de NetWatch", "high"
    elif configured_type in configured_types:
        device_type, method, confidence = configured_types[configured_type], "Tipo definido en inventario", "high"
    else:
        name = (hostname or "").lower().replace("_", "-")
        patterns = (
            (r"router|gateway|modem|(?:^|-)ont(?:-|$)", "Router"),
            (r"switch|(?:^|-)sw\d|catalyst", "Switch"),
            (r"access.?point|(?:^|-)ap\d|unifi|ubnt|eap\d|wireless", "Access Point"),
            (r"ipad|tablet|galaxy-tab", "Tablet"),
            (r"iphone|android|pixel|galaxy|redmi|smart.?phone|(?:^|-)phone(?:-|$)|movil|mobile", "Smartphone"),
            (r"printer|print|laserjet|officejet|epson|brother", "Printer"),
            (r"server|srv\d|nas(?:-|$)|proliant|poweredge", "Server"),
            (r"laptop|notebook|desktop|workstation|macbook|imac|thinkpad|windows|(?:^|-)pc(?:-|$)", "Computer"),
        )
        detected = next((category for expression, category in patterns if re.search(expression, name)), None)
        if detected:
            device_type, method, confidence = detected, "Nombre anunciado por el dispositivo", "medium"
        elif vendor in {"Samsung", "Google", "Xiaomi"}:
            device_type, method, confidence = "Smartphone", f"Fabricante MAC: {vendor}", "low"
        else:
            device_type, method, confidence = "Computer", "Equipo cliente probable; confirmar tipo", "low"

    return {
        "device_type": device_type,
        "device_type_label": DEVICE_TYPE_LABELS[device_type] + (" (probable)" if confidence in {"low", "medium"} else ""),
        "vendor": vendor,
        "identification_method": method,
        "identification_confidence": confidence,
    }


def build_parent_map(inventory: Iterable[Dict[str, Any]]) -> Dict[str, Dict[str, Any]]:
    """Build a map by IP to node metadata."""
    return {str(node["ip"]): node for node in inventory}


def build_children_map(inventory: Iterable[Dict[str, Any]]) -> Dict[str, List[str]]:
    """Create parent -> child IP relationships."""
    children: Dict[str, List[str]] = {}
    for node in inventory:
        parent_ip = node.get("parent")
        if parent_ip:
            children.setdefault(parent_ip, []).append(str(node["ip"]))
    return children


def classify_status(node: Dict[str, Any], ping_ok: bool, port_data: Dict[int, bool], conflicts: set[str], parent_status: Optional[str]) -> Dict[str, Any]:
    """Return a normalized status dictionary for a single node."""
    ip = str(node["ip"])
    status = "operational"
    reason = "Operativo"

    if ip in conflicts:
        status = "conflict"
        reason = "Conflicto de IP detectado"
    elif not ping_ok:
        if parent_status and parent_status != "operational":
            status = "inaccessible_due_to_parent"
            reason = "Inalcanzable por fallo de padre"
        else:
            status = "down"
            reason = "No responde a ICMP"
    else:
        closed_ports = [port for port, is_open in port_data.items() if not is_open]
        if closed_ports:
            status = "warning"
            reason = f"Puerto(s) cerrado(s): {', '.join(str(port) for port in closed_ports)}"

    return {
        "status": status,
        "reason": reason,
        "ip": ip,
        "name": node.get("name", ip),
        "department": node.get("department", "N/D"),
        "location": node.get("location", "N/D"),
        "type": node.get("type", "Desconocido"),
        "network": node.get("network", "wired"),
    }


def build_network_snapshot() -> Dict[str, Any]:
    """Generate the full network map and diagnostic state for the frontend."""
    config = load_config()
    configured_inventory = config.get("inventory", [])
    metadata_by_ip = {str(node.get("ip")): node for node in configured_inventory if node.get("ip")}
    network_info = get_local_network_info()

    configured_subnets = config.get("subnets", [])
    subnets = [subnet["cidr"] for subnet in configured_subnets if isinstance(subnet, dict) and subnet.get("cidr")]

    if config.get("app", {}).get("auto_detect_local_network", False):
        detected_subnets = network_info["networks"]
        for cidr in detected_subnets:
            if cidr not in subnets:
                subnets.append(cidr)

    discovered_devices: Dict[str, List[str]] = {}
    for subnet in subnets:
        try:
            discovered_devices.update(discover_network_devices(subnet))
        except Exception:
            continue

    gateway_ip = network_info.get("gateway")
    local_ips = network_info.get("local_ips", [])
    if gateway_ip:
        discovered_devices.setdefault(gateway_ip, [])
    for local_ip in local_ips:
        discovered_devices.setdefault(local_ip, [])

    root_ip = gateway_ip or (local_ips[0] if local_ips else None)
    discovered_ips = set(discovered_devices)
    hostnames: Dict[str, Optional[str]] = {}
    if discovered_ips:
        with ThreadPoolExecutor(max_workers=min(32, len(discovered_ips))) as executor:
            hostnames = dict(zip(sorted(discovered_ips), executor.map(resolve_hostname, sorted(discovered_ips))))

    merged_inventory = []
    seen_ips = set()

    if gateway_ip:
        gateway_meta = metadata_by_ip.get(gateway_ip, {})
        merged_inventory.append({
            "ip": gateway_ip,
            "name": gateway_meta.get("name", "Puerta de enlace"),
            "department": gateway_meta.get("department", "Red local"),
            "location": gateway_meta.get("location", network_info.get("interface") or "Interfaz principal"),
            "type": "Core",
            "role": "gateway",
            "parent": None,
            "network": "wired",
            "mac": next(iter(discovered_devices.get(gateway_ip, [])), None),
        })
        seen_ips.add(gateway_ip)

    for ip in sorted(discovered_ips):
        if ip in seen_ips:
            continue
        seen_ips.add(ip)
        meta = metadata_by_ip.get(ip, {})
        is_local = ip in local_ips
        hostname = hostnames.get(ip)
        merged_inventory.append({
            "ip": ip,
            "name": meta.get("name") or ("Este equipo (NetWatch)" if is_local else (hostname.split(".")[0] if hostname else f"Dispositivo {ip}")),
            "department": meta.get("department", "Red local"),
            "location": meta.get("location", network_info.get("interface") if is_local else "Red detectada"),
            "type": meta.get("type"),
            "role": "local" if is_local else "device",
            "parent": meta.get("parent") or (root_ip if ip != root_ip else None),
            "network": meta.get("network", "unknown"),
            "mac": next(iter(discovered_devices.get(ip, [])), None),
            "hostname": hostname,
        })

    for node in configured_inventory:
        ip = str(node.get("ip"))
        if ip not in seen_ips:
            configured_node = dict(node)
            configured_node.setdefault("role", "configured")
            merged_inventory.append(configured_node)
            seen_ips.add(ip)

    inventory = merged_inventory
    arp_conflicts = {
        ip: macs for ip, macs in discovered_devices.items() if len(macs) > 1
    }
    conflicts = set(arp_conflicts.keys())

    node_states: Dict[str, Dict[str, Any]] = {}
    for node in inventory:
        ip = str(node["ip"])
        ping_ok = ip in discovered_ips or ping_host(ip)
        port_data = port_scan(ip, ports=(80, 443, 22)) if ip in metadata_by_ip else {}
        parent_ip = node.get("parent")
        parent_status = None
        if parent_ip:
            parent_status = node_states.get(str(parent_ip), {}).get("status")

        state = classify_status(node, ping_ok, port_data, conflicts, parent_status)
        node_states[ip] = state

    for node in inventory:
        ip = str(node["ip"])
        parent_ip = node.get("parent")
        if not parent_ip:
            continue

        parent_state = node_states.get(parent_ip)
        if parent_state and parent_state["status"] in {"down", "conflict", "warning"}:
            if node_states[ip]["status"] not in {"conflict"}:
                node_states[ip]["status"] = "inaccessible_due_to_parent"
                node_states[ip]["reason"] = f"Inalcanzable por fallo de padre: {parent_ip}"

    nodes = []
    edges = []
    root_causes = []

    for node in inventory:
        ip = str(node["ip"])
        profile = identify_device(ip, node, gateway_ip, local_ips, node.get("hostname") or node.get("name"))
        state = node_states.get(ip, {"status": "unknown", "reason": "Sin datos"})
        node_record = {
            "id": ip,
            "label": f"{node.get('name', ip)}\n{ip}" + (f"\n{node['mac']}" if node.get("mac") else ""),
            "name": node.get("name", ip),
            "ip": ip,
            "group": node.get("type", "Desconocido"),
            "title": f"{node.get('department', 'N/D')} • {node.get('location', 'N/D')} • {node.get('role', 'device')}" + (f" • MAC {node['mac']}" if node.get("mac") else ""),
            **profile,
            "status": state["status"],
            "reason": state["reason"],
            "shape": profile["device_type"].lower().replace(" ", "-"),
            "font": {"face": "Segoe UI", "size": 12, "color": "#e5edf7"},
            "color": {
                "background": {
                    "operational": "#1d9b5f",
                    "warning": "#d6a336",
                    "down": "#d94a4a",
                    "conflict": "#f59e0b",
                    "inaccessible_due_to_parent": "#ed5f5f",
                    "unknown": "#64748b",
                }.get(state["status"], "#64748b"),
                "border": "#dfe7f5",
                "highlight": {"border": "#f8fafc", "background": "#cbd5e1"},
            },
            "size": 34 if node.get("role") in {"gateway", "local"} else 26,
            "network": node.get("network", "wired"),
            "role": node.get("role", "device"),
            "parent": node.get("parent"),
            "mac": node.get("mac"),
            "hostname": node.get("hostname"),
            "department": node.get("department", "N/D"),
            "location": node.get("location", "N/D"),
        }
        nodes.append(node_record)

        if state["status"] in {"down", "conflict", "warning", "inaccessible_due_to_parent"}:
            root_causes.append({
                "name": node.get("name", ip),
                "ip": ip,
                "department": node.get("department", "N/D"),
                "status": state["status"],
                "reason": state["reason"],
            })

        parent_ip = node.get("parent")
        if parent_ip:
            edge = {
                "from": str(parent_ip),
                "to": ip,
                "label": "",
                "title": "Asociación lógica con la puerta de enlace; no confirma el cableado físico.",
                "dashes": node.get("network") == "wireless",
                "color": {
                    "color": "#4f8af7" if node.get("network") == "wired" else "#f59e0b",
                    "highlight": "#ffffff",
                    "hover": "#f3f4f6",
                },
                "width": 2.5 if node.get("network") == "wired" else 1.8,
                "arrows": {"to": {"enabled": True, "scaleFactor": 0.8}},
                "smooth": {"enabled": True, "type": "dynamic"},
            }
            edges.append(edge)

    summary = {
        "total": len(nodes),
        "operational": sum(1 for n in nodes if n["status"] == "operational"),
        "down": sum(1 for n in nodes if n["status"] == "down"),
        "warnings": sum(1 for n in nodes if n["status"] == "warning"),
        "conflicts": sum(1 for n in nodes if n["status"] == "conflict"),
        "suppressed": sum(1 for n in nodes if n["status"] == "inaccessible_due_to_parent"),
    }
    scan_warnings = []
    if any(ipaddress.ip_network(cidr, strict=False).num_addresses > 4096 for cidr in subnets):
        scan_warnings.append("Una subred supera 4096 direcciones; se omitió el barrido masivo automático para evitar una exploración excesiva.")
    if discovered_ips and not any(discovered_devices.values()):
        scan_warnings.append("No se obtuvieron direcciones MAC por ARP. En macOS/Linux, ejecutar con privilegios elevados permite detectar también equipos que bloquean ICMP.")

    return {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "campus": config.get("app", {}).get("campus_name", "NetWatch LMR"),
        "nodes": nodes,
        "edges": edges,
        "network_info": {
            **network_info,
            "networks": subnets,
            "gateway": gateway_ip,
            "root_ip": root_ip,
            "device_count": len(nodes),
            "scan_warnings": scan_warnings,
            "topology_note": "Los enlaces muestran asociación lógica a la puerta de enlace. Para conocer conexiones físicas entre switches/AP se requiere SNMP o LLDP/CDP.",
        },
        "root_causes": root_causes,
        "summary": summary,
        "alerts": {
            "conflict_ips": sorted(arp_conflicts.keys()),
            "status_map": {node["ip"]: node["status"] for node in nodes},
        },
    }


def render_alert_message(node: Dict[str, Any], status: str, previous_status: Optional[str]) -> Optional[str]:
    """Build Telegram-ready alert text if a state transition happened."""
    if previous_status == status:
        return None

    if status in {"operational"}:
        return f"✅ Recuperado: {node['name']} ({node['ip']}) - {node['department']}"
    if status in {"down", "inaccessible_due_to_parent"}:
        return f"🚨 Fallo detectado: {node['name']} ({node['ip']}) - {node['department']} - {node['reason']}"
    if status == "warning":
        return f"⚠️ Advertencia: {node['name']} ({node['ip']}) - {node['department']} - {node['reason']}"
    if status == "conflict":
        return f"⚠️ Conflicto de IP: {node['name']} ({node['ip']}) - {node['department']} - {node['reason']}"
    return None
