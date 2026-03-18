import os
import tempfile
import statistics
from collections import defaultdict, Counter
from flask import Flask, request, jsonify, render_template
from werkzeug.utils import secure_filename

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 200 * 1024 * 1024  # 200 MB

ALLOWED_EXTENSIONS = {"pcap", "pcapng", "cap"}

# ── MAC OUI vendor table (common prefixes) ────────────────────────────────────
MAC_VENDORS = {
    "000C29": "VMware", "000569": "VMware", "001C14": "VMware", "005056": "VMware",
    "080027": "VirtualBox", "0A0027": "VirtualBox",
    "525400": "QEMU/KVM",
    "001A11": "Google", "3C5AB4": "Google", "A4C361": "Google",
    "00155D": "Microsoft Hyper-V", "001DD8": "Microsoft",
    "28D244": "Raspberry Pi", "B827EB": "Raspberry Pi", "DCA632": "Raspberry Pi",
    "ACDE48": "Apple", "000A27": "Apple", "001124": "Apple",
    "001C42": "Parallels",
    "001517": "Cisco", "00012F": "Cisco", "000142": "Cisco",
    "D4AD71": "Cisco", "F866F2": "Cisco",
    "001E58": "D-Link", "001CF0": "D-Link",
    "B4752E": "ASUSTek",
    "001018": "Broadcom",
}

# ── Port → (protocol label, host-type hint) ───────────────────────────────────
PORT_MAP = {
    20: ("FTP-Data",        "FTP Server"),
    21: ("FTP",             "FTP Server"),
    22: ("SSH",             "SSH Server"),
    23: ("Telnet",          "Telnet Server"),
    25: ("SMTP",            "Mail Server"),
    53: ("DNS",             "DNS Server"),
    67: ("DHCP",            "DHCP Server"),
    68: ("DHCP",            "DHCP Client"),
    80: ("HTTP",            "Web Server"),
    110: ("POP3",           "Mail Server"),
    119: ("NNTP",           "News Server"),
    123: ("NTP",            "NTP Server"),
    137: ("NetBIOS-NS",     "Windows Host"),
    138: ("NetBIOS-DGM",    "Windows Host"),
    139: ("NetBIOS-SSN",    "Windows Host"),
    143: ("IMAP",           "Mail Server"),
    161: ("SNMP",           "Network Device"),
    162: ("SNMP-Trap",      "Network Device"),
    179: ("BGP",            "Router"),
    389: ("LDAP",           "Directory Server"),
    443: ("HTTPS",          "Web Server"),
    445: ("SMB",            "Windows Host"),
    465: ("SMTPS",          "Mail Server"),
    514: ("Syslog",         "Log Server"),
    587: ("SMTP",           "Mail Server"),
    631: ("IPP",            "Print Server"),
    636: ("LDAPS",          "Directory Server"),
    993: ("IMAPS",          "Mail Server"),
    995: ("POP3S",          "Mail Server"),
    1433: ("MSSQL",         "Database Server"),
    1521: ("Oracle-DB",     "Database Server"),
    2375: ("Docker",        "Container Host"),
    2376: ("Docker-TLS",    "Container Host"),
    3306: ("MySQL",         "Database Server"),
    3389: ("RDP",           "Windows Host"),
    4444: ("Metasploit",    "Security Tool"),
    5432: ("PostgreSQL",    "Database Server"),
    5900: ("VNC",           "Remote Desktop"),
    5985: ("WinRM",         "Windows Host"),
    5986: ("WinRM-S",       "Windows Host"),
    6379: ("Redis",         "Cache Server"),
    6443: ("K8s-API",       "Container Host"),
    8080: ("HTTP",          "Web Server"),
    8443: ("HTTPS",         "Web Server"),
    8888: ("HTTP",          "Web Server"),
    9200: ("Elasticsearch", "Search Server"),
    27017: ("MongoDB",      "Database Server"),
    500: ("IKE/IPsec",      "VPN Gateway"),
    1194: ("OpenVPN",       "VPN Gateway"),
    1723: ("PPTP",          "VPN Gateway"),
    4500: ("IPsec-NAT",     "VPN Gateway"),
    5353: ("mDNS",          "Discovery"),
    1900: ("SSDP",          "Discovery"),
    5355: ("LLMNR",         "Windows Host"),
}

HOST_TYPE_PRIORITY = [
    "Router", "VPN Gateway", "Network Device", "DNS Server",
    "DHCP Server", "Web Server", "Mail Server", "Database Server",
    "SSH Server", "FTP Server", "Telnet Server", "Windows Host", "Directory Server",
    "Container Host", "Cache Server", "Search Server", "Log Server",
    "NTP Server", "Print Server", "Security Tool", "Remote Desktop",
]

SUSPICIOUS_PORTS = {4444, 1337, 31337, 6666, 6667, 6668}


def allowed_file(filename):
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS


def mac_vendor(mac):
    if not mac:
        return None
    prefix = mac.upper().replace(":", "").replace("-", "")[:6]
    return MAC_VENDORS.get(prefix)


def os_from_ttl(ttl):
    if ttl <= 64:
        return "Linux/Unix/macOS"
    if ttl <= 128:
        return "Windows"
    return "Network Device"


def is_private(ip):
    try:
        parts = list(map(int, ip.split(".")))
        if len(parts) != 4:
            return False
        a, b = parts[0], parts[1]
        return (
            a == 10
            or (a == 172 and 16 <= b <= 31)
            or (a == 192 and b == 168)
            or a == 127
            or (a == 169 and b == 254)
        )
    except Exception:
        return False


def geo_lookup(ip):
    try:
        import geoip2.database
        reader = geoip2.database.Reader('/usr/share/GeoIP/GeoLite2-City.mmdb')
        r = reader.city(ip)
        return {
            "country": r.country.name,
            "country_code": r.country.iso_code,
            "city": r.city.name,
            "lat": float(r.location.latitude) if r.location.latitude else None,
            "lon": float(r.location.longitude) if r.location.longitude else None,
        }
    except Exception:
        return None


def parse_http(payload_bytes, protocol):
    """Try to parse HTTP request or response from payload bytes."""
    if not payload_bytes:
        return None
    try:
        text = payload_bytes.decode("utf-8", errors="replace")
    except Exception:
        try:
            text = payload_bytes.decode("latin-1", errors="replace")
        except Exception:
            return None

    lines = text.split("\r\n")
    if not lines:
        return None
    first = lines[0]

    http_methods = ("GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS", "PATCH", "TRACE", "CONNECT")
    if any(first.startswith(m) for m in http_methods):
        # Request
        parts = first.split(" ", 2)
        if len(parts) < 2:
            return None
        method = parts[0]
        url = parts[1] if len(parts) > 1 else ""
        version = parts[2] if len(parts) > 2 else ""
        headers = {}
        body_start = 0
        for i, line in enumerate(lines[1:], 1):
            if line == "":
                body_start = i + 1
                break
            if ":" in line:
                k, v = line.split(":", 1)
                headers[k.strip()] = v.strip()
        body_preview = "\r\n".join(lines[body_start:body_start + 5]) if body_start else ""
        return {"type": "request", "method": method, "url": url, "version": version,
                "headers": headers, "body_preview": body_preview[:500]}
    elif first.startswith("HTTP/"):
        # Response
        parts = first.split(" ", 2)
        version = parts[0] if len(parts) > 0 else ""
        status_code = int(parts[1]) if len(parts) > 1 and parts[1].isdigit() else 0
        reason = parts[2] if len(parts) > 2 else ""
        headers = {}
        body_start = 0
        for i, line in enumerate(lines[1:], 1):
            if line == "":
                body_start = i + 1
                break
            if ":" in line:
                k, v = line.split(":", 1)
                headers[k.strip()] = v.strip()
        body_preview = "\r\n".join(lines[body_start:body_start + 5]) if body_start else ""
        return {"type": "response", "version": version, "status_code": status_code,
                "reason": reason, "headers": headers, "body_preview": body_preview[:500]}
    return None


def analyze_anomalies(hosts, connections, packet_store):
    """Detect network anomalies and return a list of anomaly dicts."""
    anomalies = []

    # ── Port scan: single source contacting >5 unique dst IPs with >15 unique dst ports ──
    src_dst_ips = defaultdict(set)
    src_dst_ports = defaultdict(set)
    for (a, b), conn in connections.items():
        src_dst_ips[a].add(b)
        src_dst_ips[b].add(a)
        for p in conn["dst_ports"]:
            src_dst_ports[a].add(p)
            src_dst_ports[b].add(p)

    for ip, dst_ips in src_dst_ips.items():
        if len(dst_ips) > 5 and len(src_dst_ports.get(ip, set())) > 15:
            anomalies.append({
                "type": "port_scan",
                "severity": "high",
                "src": ip,
                "dst": None,
                "description": f"{ip} contacted {len(dst_ips)} unique IPs across {len(src_dst_ports[ip])} ports — possible port scan",
            })

    # ── Cleartext credentials: FTP/Telnet connections with payload ──
    for (a, b), pkts in packet_store.items():
        for pkt in pkts:
            dport = pkt.get("dport")
            sport = pkt.get("sport")
            if dport in (21, 23) or sport in (21, 23):
                if pkt.get("hex"):
                    port = dport if dport in (21, 23) else sport
                    proto_name = "FTP" if port == 21 else "Telnet"
                    anomalies.append({
                        "type": "cleartext_creds",
                        "severity": "medium",
                        "src": pkt.get("src", a),
                        "dst": pkt.get("dst", b),
                        "description": f"Cleartext {proto_name} traffic detected between {a} and {b} — credentials may be exposed",
                    })
                    break

    # ── Beaconing: regular inter-packet timing ──
    for conn_key, pkts in packet_store.items():
        if len(pkts) < 10:
            continue
        times = [p["time"] for p in pkts]
        times.sort()
        intervals = [times[i+1] - times[i] for i in range(len(times)-1)]
        if not intervals:
            continue
        mean_interval = sum(intervals) / len(intervals)
        if mean_interval <= 0:
            continue
        try:
            std_interval = statistics.stdev(intervals)
        except statistics.StatisticsError:
            continue
        cv = std_interval / mean_interval  # coefficient of variation
        if cv < 0.2:  # < 20% of mean
            a, b = conn_key
            anomalies.append({
                "type": "beaconing",
                "severity": "medium",
                "src": a,
                "dst": b,
                "description": f"Regular beaconing detected between {a} and {b} ({len(pkts)} packets, CV={cv:.2%})",
            })

    # ── Data exfiltration: host sending >10MB to non-private IP ──
    TEN_MB = 10 * 1024 * 1024
    for ip, h in hosts.items():
        if h["bytes_sent"] > TEN_MB:
            # Check if any connections go to non-private IPs
            for (a, b) in connections:
                peer = b if a == ip else (a if b == ip else None)
                if peer and not is_private(peer):
                    anomalies.append({
                        "type": "exfiltration",
                        "severity": "high",
                        "src": ip,
                        "dst": peer,
                        "description": f"{ip} sent {h['bytes_sent'] / 1048576:.1f} MB to external IP {peer} — possible data exfiltration",
                    })
                    break

    # ── Suspicious ports ──
    for (a, b), conn in connections.items():
        for port in conn["dst_ports"]:
            if port in SUSPICIOUS_PORTS:
                anomalies.append({
                    "type": "suspicious_port",
                    "severity": "high",
                    "src": a,
                    "dst": b,
                    "description": f"Suspicious port {port} used between {a} and {b} — possible malicious activity",
                })
                break

    # Deduplicate (keep unique type+src+dst combos)
    seen = set()
    deduped = []
    for a in anomalies:
        key = (a["type"], a["src"], a["dst"])
        if key not in seen:
            seen.add(key)
            deduped.append(a)

    return deduped


def analyze_pcap(filepath):
    try:
        from scapy.all import IP, IPv6, TCP, UDP, ICMP, ARP, Ether, DNS
        from scapy.utils import PcapReader
    except ImportError as e:
        return {"error": f"scapy not available: {e}"}

    hosts = {}
    connections = defaultdict(lambda: {
        "protocols": set(),
        "packet_count": 0,
        "bytes": 0,
        "dst_ports": set(),
        "first_seen": None,
        "last_seen": None,
    })

    def host(ip, mac=None):
        if ip not in hosts:
            hosts[ip] = {
                "ip": ip,
                "mac": mac,
                "mac_vendor": mac_vendor(mac) if mac else None,
                "protocols": set(),
                "dst_ports": set(),
                "services": set(),
                "host_type_hints": Counter(),
                "ttl_values": [],
                "hostname": None,
                "dns_names": set(),
                "dns_queries": set(),
                "os_hint": None,
                "host_type": "Unknown Host",
                "packet_count": 0,
                "bytes_sent": 0,
                "bytes_recv": 0,
                "flags": set(),
                "is_private": is_private(ip),
            }
        h = hosts[ip]
        if mac and not h["mac"]:
            h["mac"] = mac
            h["mac_vendor"] = mac_vendor(mac)
        return h

    MAX_PACKETS = 150_000
    processed = 0
    packet_store = defaultdict(list)
    MAX_STORED_PER_CONN = 50
    first_pkt_time = None

    try:
        with PcapReader(filepath) as reader:
            for pkt in reader:
                if processed >= MAX_PACKETS:
                    break
                processed += 1
                if first_pkt_time is None and hasattr(pkt, "time"):
                    first_pkt_time = float(pkt.time)

                # ── ARP ──────────────────────────────────────────────────────
                if ARP in pkt:
                    try:
                        sip = pkt[ARP].psrc
                        smac = pkt[ARP].hwsrc
                        if sip and sip not in ("0.0.0.0", "255.255.255.255"):
                            h = host(sip, smac)
                            h["protocols"].add("ARP")
                    except Exception:
                        pass
                    continue

                # ── IPv4 ─────────────────────────────────────────────────────
                if IP not in pkt:
                    continue

                sip = pkt[IP].src
                dip = pkt[IP].dst
                ttl = pkt[IP].ttl
                plen = len(pkt)
                rel_t = round(float(pkt.time) - first_pkt_time, 6) if first_pkt_time else 0

                smac = pkt[Ether].src if Ether in pkt else None
                dmac = pkt[Ether].dst if Ether in pkt else None

                sh = host(sip, smac)
                dh = host(dip, dmac)

                sh["ttl_values"].append(ttl)
                sh["packet_count"] += 1
                sh["bytes_sent"] += plen
                dh["bytes_recv"] += plen

                # broadcast / multicast flags
                if dip.endswith(".255") or dip == "255.255.255.255":
                    dh["flags"].add("broadcast")
                if dip.startswith(("224.", "225.", "239.")):
                    dh["flags"].add("multicast")

                protocol = "IP"
                conn_key = tuple(sorted([sip, dip]))

                # Update connection timing
                conn = connections[conn_key]
                if conn["first_seen"] is None:
                    conn["first_seen"] = rel_t
                conn["last_seen"] = rel_t

                # ── TCP ──────────────────────────────────────────────────────
                if TCP in pkt:
                    sport = pkt[TCP].sport
                    dport = pkt[TCP].dport
                    protocol = "TCP"

                    for port, (proto, svc) in PORT_MAP.items():
                        if dport == port:
                            protocol = proto
                            dh["dst_ports"].add(port)
                            dh["services"].add(svc)
                            dh["host_type_hints"][svc] += 1
                            break
                        if sport == port:
                            protocol = proto
                            sh["dst_ports"].add(port)
                            sh["services"].add(svc)
                            sh["host_type_hints"][svc] += 1
                            break
                    else:
                        dh["dst_ports"].add(dport)

                    connections[conn_key]["dst_ports"].add(dport)

                # ── UDP ──────────────────────────────────────────────────────
                elif UDP in pkt:
                    sport = pkt[UDP].sport
                    dport = pkt[UDP].dport
                    protocol = "UDP"

                    for port, (proto, svc) in PORT_MAP.items():
                        if dport == port:
                            protocol = proto
                            dh["dst_ports"].add(port)
                            dh["services"].add(svc)
                            dh["host_type_hints"][svc] += 1
                            break
                        if sport == port:
                            protocol = proto
                            sh["dst_ports"].add(port)
                            sh["services"].add(svc)
                            sh["host_type_hints"][svc] += 1
                            break
                    else:
                        dh["dst_ports"].add(dport)

                    # DNS name extraction
                    if DNS in pkt:
                        try:
                            dns = pkt[DNS]
                            if dns.qr == 0 and dns.qdcount > 0 and dns.qd:
                                qname = dns.qd.qname
                                if isinstance(qname, bytes):
                                    qname = qname.decode("utf-8", errors="replace")
                                sh["dns_queries"].add(qname.rstrip("."))
                            elif dns.qr == 1:
                                an = dns.an
                                while an and hasattr(an, "type"):
                                    if an.type == 1:  # A record
                                        rip = an.rdata
                                        rname = an.rrname
                                        if isinstance(rip, bytes):
                                            rip = ".".join(str(b) for b in rip)
                                        if isinstance(rname, bytes):
                                            rname = rname.decode("utf-8", errors="replace")
                                        rname = rname.rstrip(".")
                                        rip_str = str(rip)
                                        if rip_str in hosts:
                                            if not hosts[rip_str]["hostname"]:
                                                hosts[rip_str]["hostname"] = rname
                                            hosts[rip_str]["dns_names"].add(rname)
                                    an = an.payload if hasattr(an, "payload") else None
                        except Exception:
                            pass

                    connections[conn_key]["dst_ports"].add(dport)

                # ── ICMP ─────────────────────────────────────────────────────
                elif ICMP in pkt:
                    protocol = "ICMP"

                sh["protocols"].add(protocol)
                dh["protocols"].add(protocol)

                conn = connections[conn_key]
                conn["protocols"].add(protocol)
                conn["packet_count"] += 1
                conn["bytes"] += plen

                # ── Per-packet capture for drill-down ────────────────────────
                if len(packet_store[conn_key]) < MAX_STORED_PER_CONN:
                    try:
                        sport_ = pkt[TCP].sport if TCP in pkt else (pkt[UDP].sport if UDP in pkt else None)
                        dport_ = pkt[TCP].dport if TCP in pkt else (pkt[UDP].dport if UDP in pkt else None)
                        pd = {
                            "time": rel_t, "src": sip, "dst": dip,
                            "protocol": protocol, "len": plen,
                            "sport": sport_, "dport": dport_,
                            "layers": [], "hex": "", "info": "",
                            "http": None,
                        }
                        if Ether in pkt:
                            e_ = pkt[Ether]
                            pd["layers"].append({"name": "Ethernet", "fields": [
                                {"k": "Dst MAC", "v": e_.dst},
                                {"k": "Src MAC", "v": e_.src},
                                {"k": "Type",    "v": hex(e_.type)},
                            ]})
                        ip_ = pkt[IP]
                        pd["layers"].append({"name": "Internet Protocol", "fields": [
                            {"k": "Version",     "v": ip_.version},
                            {"k": "Hdr Length",  "v": f"{ip_.ihl * 4} bytes"},
                            {"k": "Total Len",   "v": ip_.len},
                            {"k": "ID",          "v": hex(ip_.id)},
                            {"k": "Flags",       "v": str(ip_.flags)},
                            {"k": "TTL",         "v": ip_.ttl},
                            {"k": "Protocol",    "v": ip_.proto},
                            {"k": "Src",         "v": ip_.src},
                            {"k": "Dst",         "v": ip_.dst},
                        ]})
                        payload = b""
                        if TCP in pkt:
                            t_ = pkt[TCP]
                            flag_str = str(t_.flags)
                            pd["layers"].append({"name": "Transmission Control Protocol", "fields": [
                                {"k": "Src Port",  "v": t_.sport},
                                {"k": "Dst Port",  "v": t_.dport},
                                {"k": "Seq",       "v": t_.seq},
                                {"k": "Ack",       "v": t_.ack},
                                {"k": "Flags",     "v": flag_str},
                                {"k": "Window",    "v": t_.window},
                            ]})
                            pd["info"] = f"{t_.sport} → {t_.dport} [{flag_str}] Seq={t_.seq}"
                            payload = bytes(t_.payload)
                            if payload:
                                pd["info"] += f" Len={len(payload)}"
                        elif UDP in pkt:
                            u_ = pkt[UDP]
                            pd["layers"].append({"name": "User Datagram Protocol", "fields": [
                                {"k": "Src Port", "v": u_.sport},
                                {"k": "Dst Port", "v": u_.dport},
                                {"k": "Length",   "v": u_.len},
                            ]})
                            pd["info"] = f"{u_.sport} → {u_.dport}"
                            payload = bytes(u_.payload)
                        elif ICMP in pkt:
                            ic_ = pkt[ICMP]
                            t_names = {0: "Echo Reply", 3: "Dest Unreachable",
                                       8: "Echo Request", 11: "Time Exceeded"}
                            pd["layers"].append({"name": "Internet Control Message Protocol", "fields": [
                                {"k": "Type", "v": f"{ic_.type} ({t_names.get(ic_.type, 'Unknown')})"},
                                {"k": "Code", "v": ic_.code},
                            ]})
                            pd["info"] = t_names.get(ic_.type, f"Type {ic_.type}")
                            payload = b""

                        # HTTP parsing
                        if protocol == "HTTP" and payload:
                            pd["http"] = parse_http(payload, protocol)

                        # Store hex dump of payload
                        if payload:
                            pd["payload_hex"] = payload[:256].hex()
                        raw = bytes(pkt)[:256]
                        pd["hex"] = raw.hex()
                        packet_store[conn_key].append(pd)
                    except Exception:
                        pass

    except Exception as e:
        return {"error": f"Failed to parse file: {e}"}

    # ── Host type classification ──────────────────────────────────────────────
    for ip, h in hosts.items():
        # OS from TTL
        if h["ttl_values"]:
            common_ttl = Counter(h["ttl_values"]).most_common(1)[0][0]
            h["os_hint"] = os_from_ttl(common_ttl)

        # Broadcast / multicast shortcuts
        if "broadcast" in h["flags"] or ip.endswith(".255") or ip == "255.255.255.255":
            h["host_type"] = "Broadcast"
            continue
        if "multicast" in h["flags"] or ip.startswith(("224.", "225.", "239.")):
            h["host_type"] = "Multicast"
            continue

        # Pick best host type from accumulated hints
        if h["host_type_hints"]:
            best_hint = h["host_type_hints"].most_common(1)[0][0]
            for prio in HOST_TYPE_PRIORITY:
                if prio == best_hint:
                    h["host_type"] = prio
                    break
            else:
                h["host_type"] = best_hint
        elif h["os_hint"] == "Windows":
            h["host_type"] = "Windows Host"
        elif h["os_hint"] == "Linux/Unix/macOS":
            h["host_type"] = "Linux Host"
        elif h["os_hint"] == "Network Device":
            h["host_type"] = "Network Device"
        elif not h["is_private"]:
            h["host_type"] = "Internet Host"
        else:
            h["host_type"] = "Unknown Host"

    # ── Anomaly detection ─────────────────────────────────────────────────────
    anomalies = analyze_anomalies(hosts, connections, packet_store)

    # ── Serialise ─────────────────────────────────────────────────────────────
    nodes = []
    for ip, h in hosts.items():
        geo = None
        if not h["is_private"]:
            geo = geo_lookup(ip)
        nodes.append({
            "id": ip,
            "ip": ip,
            "mac": h["mac"],
            "mac_vendor": h["mac_vendor"],
            "hostname": h["hostname"],
            "dns_names": sorted(h["dns_names"])[:5],
            "protocols": sorted(h["protocols"]),
            "services": sorted(h["services"]),
            "open_ports": sorted(h["dst_ports"])[:30],
            "os_hint": h["os_hint"],
            "host_type": h["host_type"],
            "packet_count": h["packet_count"],
            "bytes_sent": h["bytes_sent"],
            "bytes_recv": h["bytes_recv"],
            "dns_queries": sorted(h["dns_queries"])[:10],
            "is_private": h["is_private"],
            "flags": list(h["flags"]),
            "geo": geo,
        })

    edges = []
    for (src, dst), c in connections.items():
        edges.append({
            "source": src,
            "target": dst,
            "protocols": sorted(c["protocols"]),
            "packet_count": c["packet_count"],
            "bytes": c["bytes"],
            "ports": sorted(c["dst_ports"])[:20],
            "first_seen": c["first_seen"],
            "last_seen": c["last_seen"],
        })

    all_protocols = sorted({p for n in nodes for p in n["protocols"]})
    all_host_types = sorted({n["host_type"] for n in nodes})

    # ── Build packets output (top 40 connections) ──────────────────────────
    top_conn_keys = sorted(
        connections.keys(),
        key=lambda k: connections[k]["packet_count"],
        reverse=True,
    )[:40]
    packets_out = {}
    for k in top_conn_keys:
        if packet_store[k]:
            packets_out[f"{k[0]}|{k[1]}"] = packet_store[k]

    return {
        "nodes": nodes,
        "edges": edges,
        "packets": packets_out,
        "anomalies": anomalies,
        "stats": {
            "total_packets": processed,
            "total_hosts": len(nodes),
            "total_connections": len(edges),
            "protocols": all_protocols,
            "host_types": all_host_types,
            "truncated": processed >= MAX_PACKETS,
        },
    }


def merge_results(results):
    """Merge multiple analyze_pcap result dicts into one."""
    merged_nodes = {}
    merged_edges = {}
    merged_packets = {}
    merged_anomalies = []
    anomaly_keys = set()
    total_packets = 0
    truncated = False

    for result in results:
        if "error" in result:
            continue
        total_packets += result["stats"]["total_packets"]
        if result["stats"]["truncated"]:
            truncated = True

        # Merge nodes
        for n in result["nodes"]:
            ip = n["ip"]
            if ip not in merged_nodes:
                merged_nodes[ip] = dict(n)
                merged_nodes[ip]["protocols"] = set(n["protocols"])
                merged_nodes[ip]["services"] = set(n["services"])
                merged_nodes[ip]["open_ports"] = set(n["open_ports"])
                merged_nodes[ip]["dns_names"] = set(n["dns_names"])
                merged_nodes[ip]["dns_queries"] = set(n["dns_queries"])
            else:
                mn = merged_nodes[ip]
                mn["packet_count"] += n["packet_count"]
                mn["bytes_sent"] += n["bytes_sent"]
                mn["bytes_recv"] += n["bytes_recv"]
                mn["protocols"].update(n["protocols"])
                mn["services"].update(n["services"])
                mn["open_ports"].update(n["open_ports"])
                mn["dns_names"].update(n["dns_names"])
                mn["dns_queries"].update(n["dns_queries"])
                if not mn["hostname"] and n["hostname"]:
                    mn["hostname"] = n["hostname"]
                if not mn["geo"] and n.get("geo"):
                    mn["geo"] = n["geo"]

        # Merge edges
        for e in result["edges"]:
            key = tuple(sorted([e["source"], e["target"]]))
            if key not in merged_edges:
                merged_edges[key] = {
                    "source": key[0],
                    "target": key[1],
                    "protocols": set(e["protocols"]),
                    "packet_count": e["packet_count"],
                    "bytes": e["bytes"],
                    "ports": set(e["ports"]),
                    "first_seen": e.get("first_seen"),
                    "last_seen": e.get("last_seen"),
                }
            else:
                me = merged_edges[key]
                me["packet_count"] += e["packet_count"]
                me["bytes"] += e["bytes"]
                me["protocols"].update(e["protocols"])
                me["ports"].update(e["ports"])
                if e.get("last_seen") is not None:
                    if me["last_seen"] is None or e["last_seen"] > me["last_seen"]:
                        me["last_seen"] = e["last_seen"]

        # Merge packets
        for conn_key, pkts in result["packets"].items():
            if conn_key not in merged_packets:
                merged_packets[conn_key] = pkts[:50]
            else:
                existing = merged_packets[conn_key]
                remaining = 50 - len(existing)
                if remaining > 0:
                    merged_packets[conn_key] = existing + pkts[:remaining]

        # Merge anomalies (deduplicate)
        for a in result.get("anomalies", []):
            akey = (a["type"], a["src"], a["dst"])
            if akey not in anomaly_keys:
                anomaly_keys.add(akey)
                merged_anomalies.append(a)

    # Serialize merged nodes
    nodes_out = []
    for ip, mn in merged_nodes.items():
        nodes_out.append({
            "id": ip,
            "ip": ip,
            "mac": mn["mac"],
            "mac_vendor": mn["mac_vendor"],
            "hostname": mn["hostname"],
            "dns_names": sorted(mn["dns_names"])[:5],
            "protocols": sorted(mn["protocols"]),
            "services": sorted(mn["services"]),
            "open_ports": sorted(mn["open_ports"])[:30],
            "os_hint": mn["os_hint"],
            "host_type": mn["host_type"],
            "packet_count": mn["packet_count"],
            "bytes_sent": mn["bytes_sent"],
            "bytes_recv": mn["bytes_recv"],
            "dns_queries": sorted(mn["dns_queries"])[:10],
            "is_private": mn["is_private"],
            "flags": mn.get("flags", []),
            "geo": mn.get("geo"),
        })

    edges_out = []
    for key, me in merged_edges.items():
        edges_out.append({
            "source": me["source"],
            "target": me["target"],
            "protocols": sorted(me["protocols"]),
            "packet_count": me["packet_count"],
            "bytes": me["bytes"],
            "ports": sorted(me["ports"])[:20],
            "first_seen": me.get("first_seen"),
            "last_seen": me.get("last_seen"),
        })

    all_protocols = sorted({p for n in nodes_out for p in n["protocols"]})
    all_host_types = sorted({n["host_type"] for n in nodes_out})

    return {
        "nodes": nodes_out,
        "edges": edges_out,
        "packets": merged_packets,
        "anomalies": merged_anomalies,
        "stats": {
            "total_packets": total_packets,
            "total_hosts": len(nodes_out),
            "total_connections": len(edges_out),
            "protocols": all_protocols,
            "host_types": all_host_types,
            "truncated": truncated,
        },
    }


# ── Routes ────────────────────────────────────────────────────────────────────

@app.route("/")
def index():
    return render_template("index.html")


@app.route("/upload", methods=["POST"])
def upload():
    files = request.files.getlist("file")
    if not files:
        single = request.files.get("file")
        files = [single] if single else []
    if not files or all(not f.filename for f in files):
        return jsonify({"error": "No file provided"}), 400

    results = []
    tmp_paths = []
    try:
        for f in files:
            if not f.filename:
                continue
            if not allowed_file(f.filename):
                return jsonify({"error": f"Unsupported file type: {f.filename}. Upload .pcap, .pcapng, or .cap files."}), 400
            suffix = "." + secure_filename(f.filename).rsplit(".", 1)[-1]
            tmp = tempfile.NamedTemporaryFile(suffix=suffix, delete=False)
            f.save(tmp.name)
            tmp.close()
            tmp_paths.append(tmp.name)
            results.append(analyze_pcap(tmp.name))

        if not results:
            return jsonify({"error": "No valid files processed"}), 400

        # Check for errors
        errors = [r.get("error") for r in results if "error" in r]
        if errors and len(errors) == len(results):
            return jsonify({"error": errors[0]}), 400

        result = merge_results([r for r in results if "error" not in r])
        return jsonify(result)
    finally:
        for path in tmp_paths:
            try:
                os.unlink(path)
            except OSError:
                pass


@app.route("/session-schema")
def session_schema():
    return jsonify({"status": "ok", "note": "Sessions are handled client-side only."})


if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=5000)
