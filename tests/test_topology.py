from unittest.mock import patch

from backend.topology import build_network_snapshot, identify_device
from backend.topology_detector import build_parent_mac_edges


def test_snapshot_includes_gateway_local_host_and_lan_links():
    config = {"app": {"auto_detect_local_network": True}, "subnets": [], "inventory": []}
    network_info = {
        "networks": ["192.168.1.0/24"],
        "local_ips": ["192.168.1.10"],
        "gateway": "192.168.1.1",
        "interface": "en0",
    }
    devices = {
        "192.168.1.10": [],
        "192.168.1.20": ["00:11:22:33:44:55"],
    }

    with patch("backend.topology.load_config", return_value=config), patch(
        "backend.topology.get_local_network_info", return_value=network_info
    ), patch("backend.topology.discover_network_devices", return_value=devices), patch(
        "backend.topology.ping_host", return_value=False
    ), patch("backend.topology.port_scan", return_value={}), patch(
        "backend.topology.resolve_hostname", return_value=None
    ):
        snapshot = build_network_snapshot()

    nodes = {node["ip"]: node for node in snapshot["nodes"]}
    assert nodes["192.168.1.1"]["name"] == "Puerta de enlace"
    assert nodes["192.168.1.1"]["role"] == "gateway"
    assert nodes["192.168.1.10"]["name"] == "Este equipo (NetWatch)"
    assert nodes["192.168.1.20"]["mac"] == "00:11:22:33:44:55"
    assert { (edge["from"], edge["to"]) for edge in snapshot["edges"] } == {
        ("192.168.1.1", "192.168.1.10"),
        ("192.168.1.1", "192.168.1.20"),
    }
    assert snapshot["network_info"]["root_ip"] == "192.168.1.1"
    assert nodes["192.168.1.1"]["device_type"] == "Router"
    assert nodes["192.168.1.20"]["device_type"] == "Computer"


def test_identify_device_from_hostname_and_inventory_type():
    phone = identify_device("192.168.1.25", {"type": None}, None, [], "iphone-de-nelson.local")
    switch = identify_device("192.168.1.26", {"type": "Switch"}, None, [], None)

    assert phone["device_type"] == "Smartphone"
    assert phone["identification_confidence"] == "medium"
    assert switch["device_type"] == "Switch"
    assert switch["identification_confidence"] == "high"


def test_parent_mac_edges_connect_sibling_routers_to_their_common_parent():
    nodes = [
        {"id": "AA:AA:AA:AA:AA:01", "vis_id": "AA:AA:AA:AA:AA:01", "mac": "AA:AA:AA:AA:AA:01", "device_type": "Router"},
        {"id": "BB:BB:BB:BB:BB:01", "vis_id": "BB:BB:BB:BB:BB:01", "mac": "BB:BB:BB:BB:BB:01", "parent_mac": "AA:AA:AA:AA:AA:01", "device_type": "Router"},
        {"id": "CC:CC:CC:CC:CC:01", "vis_id": "CC:CC:CC:CC:CC:01", "mac": "CC:CC:CC:CC:CC:01", "parent_mac": "AA:AA:AA:AA:AA:01", "device_type": "Router"},
    ]

    edges = build_parent_mac_edges(nodes)

    assert {(edge["from"], edge["to"]) for edge in edges} == {
        ("AA:AA:AA:AA:AA:01", "BB:BB:BB:BB:BB:01"),
        ("AA:AA:AA:AA:AA:01", "CC:CC:CC:CC:CC:01"),
    }
