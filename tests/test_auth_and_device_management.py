import asyncio
from unittest.mock import AsyncMock, patch

from fastapi.testclient import TestClient

import backend.main as main
from backend.database import DeviceInfo
from backend.main import app


client = TestClient(app)


def test_device_info_schema_uses_mac_primary_key_and_persists_parent_mac():
    assert list(DeviceInfo.__table__.primary_key.columns.keys()) == ["mac"]
    assert "parent_mac" in DeviceInfo.__table__.columns


def test_application_startup_does_not_scan_network():
    with patch("backend.main.init_db"), patch("backend.main.create_default_user"), patch(
        "backend.main.refresh_snapshot", new_callable=AsyncMock
    ) as refresh_snapshot:
        asyncio.run(main.startup_event())

    refresh_snapshot.assert_not_awaited()


def test_background_monitor_does_not_scan_without_authenticated_clients():
    original_clients = main.STATE["clients"]
    main.STATE["clients"] = []
    try:
        with patch("backend.main.refresh_snapshot", new_callable=AsyncMock) as refresh_snapshot:
            asyncio.run(main.background_monitor())
        refresh_snapshot.assert_not_awaited()
    finally:
        main.STATE["clients"] = original_clients


def test_login_and_device_updates_work_with_cookie_auth():
    login = client.post("/api/login", json={"username": "admin", "password": "admin123"})
    assert login.status_code == 200, login.text
    assert "access_token" in login.cookies

    mac = "AA:BB:CC:DD:EE:FF"
    update = client.post(
        f"/api/devices/{mac}/update",
        json={
            "custom_name": "Router Core",
            "area": "Biblioteca",
            "admin_user": "root",
            "admin_pass": "secret123",
            "ip": "192.168.1.50",
            "parent_mac": "11:22:33:44:55:66",
        },
    )
    assert update.status_code == 200, update.text

    saved = client.get(f"/api/devices/{mac}")
    assert saved.status_code == 200, saved.text
    payload = saved.json()
    assert payload["custom_name"] == "Router Core"
    assert payload["area"] == "Biblioteca"
    assert payload["admin_pass"] == "secret123"
    assert payload["parent_mac"] == "11:22:33:44:55:66"

    layout = client.post(
        "/api/layout/save",
        json={mac: {"x": 123.5, "y": -87.25}},
    )
    assert layout.status_code == 200, layout.text
    assert layout.json()["saved"] == 1

    saved_layout = client.get(f"/api/devices/{mac}")
    assert saved_layout.status_code == 200, saved_layout.text
    assert saved_layout.json()["pos_x"] == 123.5
    assert saved_layout.json()["pos_y"] == -87.25


def test_status_requires_auth_cookie():
    logout = client.post("/api/logout")
    assert logout.status_code == 200, logout.text

    with patch("backend.main.refresh_snapshot", new_callable=AsyncMock) as refresh_snapshot:
        unauth = client.get("/api/status")

    assert unauth.status_code == 401, unauth.text
    refresh_snapshot.assert_not_awaited()
