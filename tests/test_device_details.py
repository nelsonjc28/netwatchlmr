import asyncio
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest
from fastapi import HTTPException

from backend import main


def test_ipv4_address_is_not_misclassified_as_a_mac_address():
    assert main.normalize_mac("192.168.1.20") is None


def test_status_keeps_live_ip_and_edge_when_saved_ip_is_stale():
    session = MagicMock()
    session.__enter__.return_value.query.return_value.all.return_value = [
        SimpleNamespace(
            mac="AC:BC:32:C3:9D:91",
            ip="192.168.1.27",
            custom_name="mac nelson",
            area="otic",
            admin_user=None,
            admin_pass=None,
            parent_mac="00:11:22:33:44:55",
            pos_x=None,
            pos_y=None,
        )
    ]
    snapshot = {
        "nodes": [
            {"id": "192.168.1.1", "ip": "192.168.1.1", "mac": "00:11:22:33:44:55", "status": "operational"},
            {
                "id": "192.168.1.6",
                "ip": "192.168.1.6",
                "mac": "AC:BC:32:C3:9D:91",
                "name": "Este equipo (NetWatch)",
                "department": "Red local",
                "status": "operational",
            },
        ],
        "edges": [{"from": "192.168.1.1", "to": "192.168.1.6"}],
    }

    with patch("backend.main.SessionLocal", return_value=session):
        result = main.build_filtered_status_snapshot(snapshot)

    device = next(node for node in result["nodes"] if node["mac"] == "AC:BC:32:C3:9D:91")
    assert device["id"] == "AC:BC:32:C3:9D:91"
    assert device["vis_id"] == "AC:BC:32:C3:9D:91"
    assert device["ip"] == "192.168.1.6"
    assert device["custom_name"] == "mac nelson"
    assert device["parent_mac"] == "00:11:22:33:44:55"
    assert result["edges"] == [
        {
            "from": "00:11:22:33:44:55",
            "to": "AC:BC:32:C3:9D:91",
            "label": "",
            "title": "Relación padre-hijo configurada por MAC.",
            "dashes": False,
            "color": {"color": "#4f8af7", "highlight": "#ffffff"},
            "width": 2.2,
            "arrows": {"to": {"enabled": True, "scaleFactor": 0.9}},
            "smooth": {"enabled": True, "type": "dynamic"},
        }
    ]


def test_status_canonicalizes_edge_endpoints_when_device_ip_alias_is_stale():
    snapshot = {
        "nodes": [
            {"id": "192.168.1.1", "ip": "192.168.1.1", "status": "operational"},
            {"id": "192.168.1.6", "ip": "192.168.1.27", "status": "operational"},
        ],
        "edges": [{"from": "192.168.1.1", "to": "192.168.1.6"}],
    }

    with patch("backend.main.attach_db_metadata", return_value=snapshot["nodes"]):
        result = main.build_filtered_status_snapshot(snapshot)

    assert result["edges"] == snapshot["edges"]


def test_device_details_only_scans_devices_from_current_snapshot():
    node = {
        "id": "192.168.1.20",
        "ip": "192.168.1.20",
        "name": "Host 192.168.1.20",
        "mac": "00:11:22:33:44:55",
        "device_type": "Computer",
    }
    original_snapshot = main.STATE["snapshot"]
    main.STATE["snapshot"] = {"nodes": [node]}
    try:
        with patch("backend.main.require_auth"), patch(
            "backend.main.ping_details", return_value={"reachable": True, "latency_ms": 2.4}
        ), patch("backend.main.scan_open_tcp_ports", return_value=[22, 443]):
            result = asyncio.run(main.get_device_details("192.168.1.20", request=object()))
    finally:
        main.STATE["snapshot"] = original_snapshot

    assert result["device"] == node
    assert result["diagnostics"]["reachable"] is True
    assert result["diagnostics"]["latency_ms"] == 2.4
    assert result["diagnostics"]["open_tcp_ports"] == [
        {"port": 22, "service": "SSH"},
        {"port": 443, "service": "HTTPS"},
    ]


def test_device_details_rejects_ip_not_in_current_snapshot():
    original_snapshot = main.STATE["snapshot"]
    main.STATE["snapshot"] = {"nodes": []}
    try:
        with patch("backend.main.require_auth"), pytest.raises(HTTPException) as error:
            asyncio.run(main.get_device_details("192.168.1.20", request=object()))
    finally:
        main.STATE["snapshot"] = original_snapshot

    assert error.value.status_code == 404
