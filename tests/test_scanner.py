from unittest.mock import patch

from scapy.error import Scapy_Exception

from backend.scanner import arp_scan, detect_local_networks, get_default_route_info, get_interface_networks, system_arp_scan


def test_arp_scan_handles_permission_error():
    with patch("backend.scanner.srp", side_effect=Scapy_Exception("Permission denied: could not open /dev/bpf0")):
        assert arp_scan("192.168.10.0/24") == {}


def test_detect_local_networks_uses_device_ip():
    with patch("backend.scanner.get_default_route_info", return_value={}), patch(
        "backend.scanner.get_interface_networks", return_value=[]
    ), patch("backend.scanner.get_local_ip_addresses", return_value=["192.168.1.25"]):
        assert detect_local_networks() == ["192.168.1.0/24"]


def test_interface_network_uses_reported_netmask():
    ifconfig = """en0: flags=8863<UP,BROADCAST,RUNNING,SIMPLEX,MULTICAST>\n\tinet 10.24.16.8 netmask 0xfffff000 broadcast 10.24.31.255\n"""
    with patch("backend.scanner.subprocess.run", return_value=type("Result", (), {"stdout": ifconfig})()):
        assert get_interface_networks("en0") == ["10.24.16.0/20"]


def test_default_route_reads_gateway_and_interface():
    route_output = "gateway: 192.168.1.1\ninterface: en0\n"
    with patch("backend.scanner.subprocess.run", return_value=type("Result", (), {"stdout": route_output})()):
        assert get_default_route_info() == {"gateway": "192.168.1.1", "interface": "en0"}


def test_system_arp_scan_reads_mac_without_scapy():
    arp_output = "? (192.168.1.20) at 0:11:22:33:44:55 on en0 ifscope [ethernet]\n? (192.168.2.5) at aa:bb:cc:dd:ee:ff on en0\n"
    with patch("backend.scanner.subprocess.run", return_value=type("Result", (), {"stdout": arp_output})()):
        assert system_arp_scan("192.168.1.0/24") == {"192.168.1.20": ["00:11:22:33:44:55"]}
