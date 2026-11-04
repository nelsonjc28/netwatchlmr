"""Utilities for resolving saved MAC-based parent/child topology relationships."""

import re
from typing import Any, Dict, List


def normalize_mac(value: Any) -> str | None:
    if value is None:
        return None
    cleaned = str(value).strip().upper().replace("-", ":").replace(" ", "")
    if re.fullmatch(r"[0-9A-F]{12}", cleaned):
        return ":".join(cleaned[index : index + 2] for index in range(0, 12, 2))
    if re.fullmatch(r"(?:[0-9A-F]{2}:){5}[0-9A-F]{2}", cleaned):
        return cleaned
    return None


def build_parent_mac_edges(nodes: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Resolve saved parent MACs to active node IDs; shared parents define siblings."""
    mac_counts: Dict[str, int] = {}
    for node in nodes:
        mac = normalize_mac(node.get("mac"))
        if mac:
            mac_counts[mac] = mac_counts.get(mac, 0) + 1

    node_id_by_mac: Dict[str, str] = {}
    for node in nodes:
        mac = normalize_mac(node.get("mac"))
        if mac and mac_counts[mac] == 1:
            node_id_by_mac[mac] = str(node.get("vis_id") or node.get("id") or node.get("ip"))

    edges = []
    for child in nodes:
        parent_mac = normalize_mac(child.get("parent_mac"))
        child_mac = normalize_mac(child.get("mac"))
        if not parent_mac or parent_mac not in node_id_by_mac:
            continue

        child_id = str(child.get("vis_id") or child.get("id") or child.get("ip"))
        parent_id = node_id_by_mac[parent_mac]
        if not child_id or parent_id == child_id or parent_mac == child_mac:
            continue

        edges.append(
            {
                "from": parent_id,
                "to": child_id,
                "label": "",
                "title": "Relación padre-hijo configurada por MAC.",
                "dashes": False,
                "color": {"color": "#4f8af7", "highlight": "#ffffff"},
                "width": 2.2,
                "arrows": {"to": {"enabled": True, "scaleFactor": 0.9}},
                "smooth": {"enabled": True, "type": "dynamic"},
            }
        )

    return edges
