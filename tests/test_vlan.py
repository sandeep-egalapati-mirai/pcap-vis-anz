"""Tests for VLAN tag (802.1Q / QinQ) parsing and VLAN anomaly detection."""
import sys
import os
import tempfile
import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app import analyze_pcap, merge_results, analyze_anomalies

try:
    from scapy.utils import wrpcap
    from scapy.layers.l2 import Ether, Dot1Q, Dot1AD
    from scapy.layers.inet import IP, TCP, UDP
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False

pytestmark = pytest.mark.skipif(not SCAPY_AVAILABLE, reason="scapy not installed")

MAC_A = "aa:bb:cc:11:00:01"
MAC_B = "aa:bb:cc:11:00:02"
MAC_C = "aa:bb:cc:11:00:03"
MAC_D = "aa:bb:cc:11:00:04"
IP_A  = "10.10.1.1"
IP_B  = "10.10.2.1"
IP_C  = "10.10.3.1"
IP_D  = "10.10.4.1"


def _write(path, pkts):
    wrpcap(str(path), pkts)


def _analyze(pkts):
    with tempfile.NamedTemporaryFile(suffix=".pcap", delete=False) as f:
        _write(f.name, pkts)
        result = analyze_pcap(f.name)
    os.unlink(f.name)
    return result


def _node(result, ip):
    return next((n for n in result["nodes"] if n["ip"] == ip), None)


# ── Single 802.1Q tag ─────────────────────────────────────────────────────────

def test_single_vlan_tag_extracted():
    pkts = [
        Ether(src=MAC_A, dst=MAC_B) / Dot1Q(vlan=10, prio=2) /
        IP(src=IP_A, dst=IP_B) / TCP(sport=50001, dport=80, flags="S"),
        Ether(src=MAC_B, dst=MAC_A) / Dot1Q(vlan=10, prio=2) /
        IP(src=IP_B, dst=IP_A) / TCP(sport=80, dport=50001, flags="SA"),
    ]
    r = _analyze(pkts)
    assert "error" not in r
    assert 10 in (r["stats"]["vlans"] or [])
    assert r["stats"]["vlans_detected"] >= 1

    na = _node(r, IP_A)
    nb = _node(r, IP_B)
    assert na is not None and nb is not None
    assert 10 in na["vlans"]
    assert 10 in nb["vlans"]
    assert 2 in na["vlan_pcps"]
    assert not na["vlan_untagged"]
    assert not na["vlan_qinq"]


def test_multiple_vlans_different_hosts():
    pkts = [
        Ether(src=MAC_A, dst=MAC_B) / Dot1Q(vlan=10) /
        IP(src=IP_A, dst=IP_B) / TCP(sport=50001, dport=80, flags="S"),
        Ether(src=MAC_C, dst=MAC_D) / Dot1Q(vlan=20) /
        IP(src=IP_C, dst=IP_D) / TCP(sport=50002, dport=443, flags="S"),
    ]
    r = _analyze(pkts)
    vlans = r["stats"]["vlans"]
    assert 10 in vlans
    assert 20 in vlans
    assert r["stats"]["vlans_detected"] == 2


def test_untagged_frame_no_vlan_fields():
    pkts = [
        Ether(src=MAC_A, dst=MAC_B) / IP(src=IP_A, dst=IP_B) /
        TCP(sport=50001, dport=80, flags="S"),
    ]
    r = _analyze(pkts)
    assert r["stats"]["vlans_detected"] == 0
    na = _node(r, IP_A)
    assert na is not None
    assert na["vlans"] == []
    assert na["vlan_untagged"] is True
    assert na["vlan_qinq"] is False


def test_vlan_id_in_edge():
    pkts = [
        Ether(src=MAC_A, dst=MAC_B) / Dot1Q(vlan=42) /
        IP(src=IP_A, dst=IP_B) / TCP(sport=50001, dport=80, flags="S"),
        Ether(src=MAC_B, dst=MAC_A) / Dot1Q(vlan=42) /
        IP(src=IP_B, dst=IP_A) / TCP(sport=80, dport=50001, flags="SA"),
    ]
    r = _analyze(pkts)
    edges = r["edges"]
    assert len(edges) >= 1
    edge = next((e for e in edges if set([e["source"], e["target"]]) == {IP_A, IP_B}), None)
    assert edge is not None
    assert 42 in edge["vlans"]


# ── QinQ (802.1ad double-tagged) ──────────────────────────────────────────────

def test_qinq_outer_inner_vlan_extracted():
    pkts = [
        Ether(src=MAC_A, dst=MAC_B) / Dot1AD(vlan=100) / Dot1Q(vlan=200, prio=4) /
        IP(src=IP_A, dst=IP_B) / TCP(sport=50001, dport=80, flags="S"),
    ]
    r = _analyze(pkts)
    na = _node(r, IP_A)
    assert na is not None
    assert na["vlan_qinq"] is True
    assert 200 in na["vlans"]
    assert 100 in na["vlan_outer"]
    assert 4 in na["vlan_pcps"]


# ── JSON round-trip: VLAN fields present on all nodes ─────────────────────────

def test_vlan_fields_present_on_all_nodes():
    pkts = [
        Ether(src=MAC_A, dst=MAC_B) / Dot1Q(vlan=15) /
        IP(src=IP_A, dst=IP_B) / UDP(sport=1000, dport=1001),
    ]
    r = _analyze(pkts)
    for node in r["nodes"]:
        assert "vlans" in node
        assert "vlan_outer" in node
        assert "vlan_pcps" in node
        assert "vlan_untagged" in node
        assert "vlan_qinq" in node
    assert "vlans" in r["stats"]
    assert "vlans_detected" in r["stats"]


# ── Merge: VLAN sets unioned across PCAPs ─────────────────────────────────────

def test_merge_vlan_sets_unioned():
    pkts1 = [
        Ether(src=MAC_A, dst=MAC_B) / Dot1Q(vlan=10) /
        IP(src=IP_A, dst=IP_B) / TCP(sport=50001, dport=80, flags="S"),
    ]
    pkts2 = [
        Ether(src=MAC_A, dst=MAC_B) / Dot1Q(vlan=20) /
        IP(src=IP_A, dst=IP_B) / TCP(sport=50002, dport=80, flags="S"),
    ]
    r1 = _analyze(pkts1)
    r2 = _analyze(pkts2)
    merged = merge_results([r1, r2])
    na = next((n for n in merged["nodes"] if n["ip"] == IP_A), None)
    assert na is not None
    assert 10 in na["vlans"]
    assert 20 in na["vlans"]
    assert merged["stats"]["vlans_detected"] == 2


def test_merge_vlan_untagged_ored():
    pkts1 = [
        Ether(src=MAC_A, dst=MAC_B) / IP(src=IP_A, dst=IP_B) /
        TCP(sport=50001, dport=80, flags="S"),
    ]
    pkts2 = [
        Ether(src=MAC_A, dst=MAC_B) / Dot1Q(vlan=10) /
        IP(src=IP_A, dst=IP_B) / TCP(sport=50002, dport=80, flags="S"),
    ]
    r1 = _analyze(pkts1)
    r2 = _analyze(pkts2)
    merged = merge_results([r1, r2])
    na = next((n for n in merged["nodes"] if n["ip"] == IP_A), None)
    assert na["vlan_untagged"] is True
    assert 10 in na["vlans"]


# ── Anomaly detection ─────────────────────────────────────────────────────────

def _make_host(vlan_ids=None, vlan_untagged=False, vlan_qinq=False, vlan_outer_ids=None,
               host_type="Windows Host", ot_role="unknown", is_private=True, bytes_sent=0):
    return {
        "bytes_sent": bytes_sent,
        "bytes_recv": 0,
        "host_type": host_type,
        "packet_count": 1,
        "is_private": is_private,
        "vlan_ids": set(vlan_ids or []),
        "vlan_untagged": vlan_untagged,
        "vlan_qinq": vlan_qinq,
        "vlan_outer_ids": set(vlan_outer_ids or []),
        "vlan_pcps": set(),
        "ot_role": ot_role,
        "tls_ja3": set(),
        "dns_queries": set(),
        "modbus_unit_ids": set(),
    }


def _conn(dst_ports=None, packet_count=1, bytes_total=0, vlan_ids=None):
    return {
        "dst_ports": set(dst_ports or []),
        "packet_count": packet_count,
        "bytes": bytes_total,
        "vlan_ids": set(vlan_ids or []),
    }


def test_vlan_hopping_detected():
    hosts = {
        "10.0.0.1": _make_host(vlan_ids={10, 20}, host_type="Windows Host"),
        "10.0.0.2": _make_host(vlan_ids={10}),
    }
    connections = {("10.0.0.1", "10.0.0.2"): _conn(vlan_ids={10})}
    anomalies = analyze_anomalies(hosts, connections, {})
    types = {a["type"] for a in anomalies}
    assert "vlan_hopping" in types
    a = next(x for x in anomalies if x["type"] == "vlan_hopping")
    assert a["src"] == "10.0.0.1"
    assert a["severity"] == "medium"


def test_vlan_native_leak_detected():
    hosts = {
        "10.0.0.1": _make_host(vlan_ids={10}, vlan_untagged=True),
        "10.0.0.2": _make_host(vlan_ids={10}),
    }
    connections = {("10.0.0.1", "10.0.0.2"): _conn(vlan_ids={10})}
    anomalies = analyze_anomalies(hosts, connections, {})
    types = {a["type"] for a in anomalies}
    assert "vlan_native_leak" in types
    a = next(x for x in anomalies if x["type"] == "vlan_native_leak")
    assert a["severity"] == "low"


def test_vlan_qinq_anomaly_detected():
    hosts = {
        "10.0.0.1": _make_host(vlan_ids={200}, vlan_qinq=True, vlan_outer_ids={100}),
        "10.0.0.2": _make_host(vlan_ids={200}),
    }
    connections = {("10.0.0.1", "10.0.0.2"): _conn(vlan_ids={200})}
    anomalies = analyze_anomalies(hosts, connections, {})
    types = {a["type"] for a in anomalies}
    assert "vlan_qinq" in types
    a = next(x for x in anomalies if x["type"] == "vlan_qinq")
    assert a["severity"] == "medium"


def test_vlan_cross_segment_ot_detected():
    hosts = {
        "10.0.0.10": _make_host(vlan_ids={10}, host_type="PLC", ot_role="outstation"),
        "10.0.0.20": _make_host(vlan_ids={20}, host_type="Windows Host"),
    }
    connections = {
        ("10.0.0.10", "10.0.0.20"): _conn(dst_ports={502}, vlan_ids={10}),
    }
    anomalies = analyze_anomalies(hosts, connections, {})
    types = {a["type"] for a in anomalies}
    assert "vlan_cross_segment_ot" in types
    a = next(x for x in anomalies if x["type"] == "vlan_cross_segment_ot")
    assert a["severity"] == "high"


def test_no_vlan_cross_segment_same_vlan():
    hosts = {
        "10.0.0.10": _make_host(vlan_ids={10}, host_type="PLC", ot_role="outstation"),
        "10.0.0.20": _make_host(vlan_ids={10}, host_type="Windows Host"),
    }
    connections = {
        ("10.0.0.10", "10.0.0.20"): _conn(dst_ports={502}, vlan_ids={10}),
    }
    anomalies = analyze_anomalies(hosts, connections, {})
    types = {a["type"] for a in anomalies}
    assert "vlan_cross_segment_ot" not in types
