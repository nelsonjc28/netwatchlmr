import ipaddress
import json
import re
import socket
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any, Dict, Iterable, List, Tuple

try:
    from scapy.all import ARP, Ether, srp
except ImportError:  # pragma: no cover - optional dependency for limited environments
    ARP = Ether = srp = None

ROOT_DIR = Path(__file__).resolve().parents[1]
CONFIG_PATH = ROOT_DIR / "config.json"


def load_config() -> Dict[str, Any]:
    with CONFIG_PATH.open("r", encoding="utf-8") as file:
        return json.load(file)


def get_local_ip_addresses() -> List[str]:
    """Return the non-loopback IPv4 addresses assigned to the host."""
    candidates: List[str] = []

    try:
        hostname = socket.gethostname()
        info = socket.getaddrinfo(hostname, None, type=socket.SOCK_DGRAM)
        for family, _, _, _, sockaddr in info:
            if family == socket.AF_INET:
                ip = sockaddr[0]
                if ip and not ip.startswith("127.") and not ip.startswith("169.254."):
                    candidates.append(ip)
    except OSError:
        pass

    if not candidates:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
                sock.connect(("8.8.8.8", 80))
                ip = sock.getsockname()[0]
                if ip and not ip.startswith("127."):
                    candidates.append(ip)
        except OSError:
            pass

    if not candidates:
        for iface in ("en0", "en1", "eth0", "wlan0", "Wi-Fi"):
            try:
                result = subprocess.run(["ipconfig", "getifaddr", iface], capture_output=True, text=True, check=False)
                ip = result.stdout.strip()
                if ip and not ip.startswith("127."):
                    candidates.append(ip)
            except FileNotFoundError:
                pass

    unique = []
    for item in candidates:
        if item not in unique:
            unique.append(item)
    return unique


def infer_network_prefix(ip: str) -> int:
    """Return a conservative fallback prefix when the interface mask is unknown."""
    return 24


def get_default_route_info() -> Dict[str, str]:
    """Return the default gateway and interface reported by the operating system."""
    try:
        result = subprocess.run(["route", "-n", "get", "default"], capture_output=True, text=True, check=False)
        values: Dict[str, str] = {}
        for line in (result.stdout or "").splitlines():
            key, separator, value = line.strip().partition(":")
            if separator and key.lower() in {"gateway", "interface"}:
                values[key.lower()] = value.strip()
        if values:
            return values
    except FileNotFoundError:
        pass

    try:
        result = subprocess.run(["ip", "-4", "route", "show", "default"], capture_output=True, text=True, check=False)
        match = re.search(r"\bvia\s+(\S+).*?\bdev\s+(\S+)", result.stdout or "")
        if match:
            return {"gateway": match.group(1), "interface": match.group(2)}
    except FileNotFoundError:
        pass

    return {}


def get_interface_networks(interface: str = "") -> List[str]:
    """Read assigned IPv4 CIDRs from ifconfig, preserving the actual netmask."""
    try:
        result = subprocess.run(["ifconfig"], capture_output=True, text=True, check=False)
    except FileNotFoundError:
        return []

    networks: List[str] = []
    current_interface = ""
    for line in (result.stdout or "").splitlines():
        if line and not line[0].isspace() and ":" in line:
            current_interface = line.split(":", 1)[0].split("@", 1)[0]
        if interface and current_interface != interface:
            continue
        match = re.search(r"\binet\s+(\d+(?:\.\d+){3})\s+netmask\s+(0x[\da-fA-F]+|\d+(?:\.\d+){3})", line)
        if not match:
            continue
        ip, mask = match.groups()
        if ip.startswith(("127.", "169.254.")):
            continue
        try:
            if mask.startswith("0x"):
                mask = socket.inet_ntoa(int(mask, 16).to_bytes(4, "big"))
            networks.append(str(ipaddress.ip_interface(f"{ip}/{mask}").network))
        except (ValueError, OverflowError):
            continue
    return sorted(set(networks))


def detect_local_networks() -> List[str]:
    """Detect the LAN CIDR(s) using the active interface's real subnet mask."""
    route_info = get_default_route_info()
    networks = get_interface_networks(route_info.get("interface", ""))
    if networks:
        return networks

    networks = []
    local_ips = get_local_ip_addresses()
    for ip in local_ips:
        try:
            prefix = infer_network_prefix(ip)
            network = ipaddress.ip_network(f"{ip}/{prefix}", strict=False)
            networks.append(str(network))
        except ValueError:
            continue

    if not networks and route_info.get("gateway"):
        try:
            networks.append(str(ipaddress.ip_network(f"{route_info['gateway']}/24", strict=False)))
        except ValueError:
            pass

    return sorted(set(networks))


def get_local_network_info() -> Dict[str, Any]:
    """Return the detected LAN, gateway and local addresses for the topology view."""
    route_info = get_default_route_info()
    return {
        "networks": detect_local_networks(),
        "local_ips": get_local_ip_addresses(),
        "gateway": route_info.get("gateway"),
        "interface": route_info.get("interface"),
    }


def ping_host(ip: str, timeout: float = 1.5) -> bool:
    """Return True when the host answers ICMP echo."""
    try:
        process = subprocess.run(
            ["ping", "-c", "1", "-W", str(timeout), str(ip)],
            capture_output=True,
            text=True,
            timeout=max(3.0, timeout + 1.0),
            check=False,
        )
        return process.returncode == 0
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return False


def ping_details(ip: str, timeout: float = 1.5) -> Dict[str, Any]:
    """Return ICMP reachability and round-trip time when the host responds."""
    try:
        process = subprocess.run(
            ["ping", "-c", "1", "-W", str(timeout), str(ip)],
            capture_output=True,
            text=True,
            timeout=max(3.0, timeout + 1.0),
            check=False,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return {"reachable": False, "latency_ms": None}

    output = f"{process.stdout or ''}\n{process.stderr or ''}"
    match = re.search(r"time[=<]([\d.]+)\s*ms", output, re.IGNORECASE)
    return {
        "reachable": process.returncode == 0,
        "latency_ms": float(match.group(1)) if match else None,
    }


def scan_open_tcp_ports(ip: str, ports: Iterable[int] = (22, 53, 80, 443, 445, 548, 631, 3389, 5000, 8080, 8443), timeout: float = 0.4) -> List[int]:
    """Quickly probe a bounded set of common TCP ports for a selected LAN device."""
    ports = tuple(int(port) for port in ports)

    def is_open(port: int) -> bool:
        try:
            with socket.create_connection((str(ip), port), timeout=timeout):
                return True
        except (OSError, socket.timeout):
            return False

    with ThreadPoolExecutor(max_workers=max(1, len(ports))) as executor:
        results = list(executor.map(is_open, ports))
    return [port for port, opened in zip(ports, results) if opened]


def traceroute_host(ip: str, max_hops: int = 12) -> List[str]:
    """Collect intermediate hops for a host using traceroute."""
    try:
        process = subprocess.run(
            ["traceroute", "-n", "-w", "1", "-m", str(max_hops), str(ip)],
            capture_output=True,
            text=True,
            timeout=max(6.0, max_hops),
            check=False,
        )
        if process.returncode not in (0, 1):
            return []

        hops: List[str] = []
        for line in process.stdout.splitlines():
            parts = line.strip().split()
            if len(parts) >= 2 and parts[0].isdigit():
                hops.append(parts[-1])
        return hops
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return []


def port_scan(ip: str, ports: Iterable[int] = (80, 443, 22)) -> Dict[int, bool]:
    """Check which TCP ports are open on an IP."""
    results: Dict[int, bool] = {}
    for port in ports:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1.2)
        try:
            sock.connect((str(ip), int(port)))
            results[int(port)] = True
        except (OSError, socket.timeout):
            results[int(port)] = False
        finally:
            sock.close()
    return results


def system_arp_scan(cidr: str) -> Dict[str, List[str]]:
    """Read the OS neighbor cache, which is available without raw-socket access."""
    network = ipaddress.ip_network(cidr, strict=False)
    try:
        result = subprocess.run(["arp", "-an"], capture_output=True, text=True, check=False, timeout=4)
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return {}

    devices: Dict[str, List[str]] = {}
    pattern = re.compile(r"\((\d+(?:\.\d+){3})\)\s+at\s+([0-9a-fA-F:]{11,17})")
    for line in (result.stdout or "").splitlines():
        match = pattern.search(line)
        if not match:
            continue
        ip, raw_mac = match.groups()
        try:
            if ipaddress.ip_address(ip) not in network:
                continue
            octets = raw_mac.lower().split(":")
            mac = ":".join(octet.zfill(2) for octet in octets)
            if len(octets) == 6:
                devices.setdefault(ip, []).append(mac)
        except ValueError:
            continue
    return {ip: sorted(set(macs)) for ip, macs in devices.items()}


def resolve_hostname(ip: str) -> str | None:
    """Resolve a LAN host name using the platform's local name service."""
    command = ["dscacheutil", "-q", "host", "-a", "ip_address", ip] if sys.platform == "darwin" else ["getent", "hosts", ip]
    try:
        result = subprocess.run(command, capture_output=True, text=True, check=False, timeout=0.8)
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return None

    for line in (result.stdout or "").splitlines():
        tokens = line.split()
        if not tokens:
            continue
        candidate = next((token.rstrip(".") for token in tokens if token.lower() not in {"name:", ip.lower()} and token.lower() != "ip_address:"), None)
        if candidate and candidate.lower() != ip.lower():
            return candidate
    return None


def discover_network_devices(cidr: str, worker_count: int = 128) -> Dict[str, List[str]]:
    """Discover devices through ARP and ICMP, retaining MAC addresses when available."""
    network = ipaddress.ip_network(cidr, strict=False)
    arp_devices = arp_scan(cidr) if network.num_addresses <= 4096 else {}
    found_ips = set(arp_devices)
    hosts = [str(ip) for ip in network.hosts()]

    # ARP usually finds silent hosts on a LAN. Fall back to ICMP for small/medium
    # networks; avoid an unbounded multi-minute ping sweep on very large subnets.
    if network.num_addresses <= 4096:
        with ThreadPoolExecutor(max_workers=min(worker_count, len(hosts) or 1)) as executor:
            ping_results = list(executor.map(ping_host, hosts))
        found_ips.update(host for host, is_up in zip(hosts, ping_results) if is_up)

    # The ICMP sweep populates the kernel neighbor table even when Scapy cannot
    # open a raw packet socket (common on macOS without elevated privileges).
    arp_devices.update(system_arp_scan(cidr))
    found_ips.update(arp_devices)
    return {ip: arp_devices.get(ip, []) for ip in sorted(found_ips)}


def discover_live_hosts(cidr: str, worker_count: int = 128) -> List[str]:
    """Compatibility wrapper returning the IPs of discovered LAN devices."""
    return list(discover_network_devices(cidr, worker_count=worker_count))


def arp_scan(subnet: str) -> Dict[str, List[str]]:
    """Scan a subnet via ARP and return a map of IP -> MACs seen."""
    if ARP is None or Ether is None or srp is None:
        return {}

    try:
        if ipaddress.ip_network(subnet, strict=False).num_addresses > 4096:
            return {}
        ans, _ = srp(Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=subnet), timeout=2, verbose=False)
    except Exception:
        return {}

    observed: Dict[str, List[str]] = {}
    for _, response in ans or []:
        ip = response.psrc
        mac = response.hwsrc
        observed.setdefault(ip, []).append(mac)

    return {ip: sorted(set(macs)) for ip, macs in observed.items() if macs}


def detect_arp_conflicts(subnets: Iterable[str]) -> Dict[str, List[str]]:
    """Return IPs that have multiple MAC addresses responding to the same target."""
    conflicts: Dict[str, List[str]] = {}
    for subnet in subnets:
        scan_results = arp_scan(subnet)
        for ip, macs in scan_results.items():
            if len(macs) > 1:
                conflicts[ip] = macs
    return conflicts
