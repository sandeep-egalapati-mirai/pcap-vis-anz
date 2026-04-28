# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Workflow

After completing any change:
1. Update `README.md` to reflect the change (new protocols, updated limits, new features, etc.)
2. Commit and push to GitHub:

```bash
git add <changed files>
git commit -m "your message"
git push
```

## Running the app

```bash
pip install -r requirements.txt          # first time; add --break-system-packages on Kali/Debian
python app.py                            # serves on http://localhost:5000
```

No build step, no test suite, no linter config. Changes to Python or JS/CSS take effect on the next request (Flask debug mode is on).

To change the port, edit the last line of `app.py`.

## Architecture

A single-page Flask app with three files of substance:

- **`app.py`** — entire Python backend (~1,340 lines)
- **`static/js/app.js`** — entire frontend (~1,810 lines, vanilla JS + D3.js v7)
- **`static/css/style.css`** — dark GitHub-style theme (~1,130 lines)
- **`templates/index.html`** — static HTML shell, no Jinja logic

D3.js v7 is bundled locally at `static/js/d3.v7.min.js` for air-gapped use; don't CDN-ify it.

### Backend (`app.py`)

**Data flow:** `POST /upload` → save to `tempfile` → `analyze_pcap()` per file → `merge_results()` → JSON response → `GET /` renders the shell.

Key functions in call order:

| Function | Purpose |
|---|---|
| `analyze_pcap(filepath)` | Streams PCAP via scapy `PcapReader`; builds `hosts` dict and `connections` defaultdict; calls protocol parsers on matching ports; caps at 1,000,000 packets and 50 stored packets per connection |
| `merge_results(results)` | Merges multiple `analyze_pcap` results for multi-file uploads; deduplicates anomalies |
| `analyze_anomalies(hosts, connections, packet_store)` | Detects port scans, cleartext credentials, beaconing (CV < 0.2), exfiltration (>10 MB to external), suspicious ports, OT/IoT-specific issues |
| `parse_http / parse_modbus / parse_mqtt / parse_coap` | Deep-inspection parsers called per packet when the port matches |

**Constants to know when adding protocols:**
- `PORT_MAP` — maps port number → `(protocol_label, host_type_hint)` for both TCP and UDP
- `MAC_VENDORS` — OUI prefix → vendor name (6 hex chars, no separators)
- `HOST_TYPE_PRIORITY` — ordered list; first match wins during host classification
- `SUSPICIOUS_PORTS` — set of ports that trigger `suspicious_port` anomaly

**Host classification** runs after the packet loop: TTL → OS hint, then `host_type_hints` counter resolved against `HOST_TYPE_PRIORITY`.

**GeoIP** (`geo_lookup`) is optional; silently returns `None` if `geoip2` can't open `/usr/share/GeoIP/GeoLite2-City.mmdb`.

### Frontend (`static/js/app.js`)

**Global state:**
- `graphData` — the parsed JSON from `/upload` (`nodes`, `edges`, `packets`, `anomalies`, `stats`)
- `packetData` — packet drill-down data, keyed `"srcIP|dstIP"`
- `simulation` — D3 force simulation instance
- `activeProtos` / `activeTypes` — Sets driving sidebar filter visibility
- `currentView` — `"graph"` | `"table"` | `"dns"`
- `currentLayout` — `"force"` | `"radial"` | `"cluster"`

**Rendering pipeline:** upload → `renderGraph(data)` → builds SVG nodes/edges → `buildSidebar()` populates filter checkboxes → `applyFilters()` shows/hides elements. Switching layouts calls `applyLayout()`.

**Node detail panel** (right sidebar): clicking a node populates `#detail-panel` with host metadata and a packet table for that connection. Protocol deep-inspection results (HTTP, Modbus, MQTT, CoAP) are rendered here.

**Color maps** (`HOST_COLORS`, `PROTO_COLORS`) at the top of `app.js` must stay in sync with any new host types or protocols added to `PORT_MAP`.

## Key limits (change in `app.py`)

| Limit | Default | Location |
|---|---|---|
| Max upload size | 1 GB | `app.config["MAX_CONTENT_LENGTH"]` |
| Max packets parsed | 1,000,000 | `MAX_PACKETS` in `analyze_pcap()` |
| Stored packets per connection | 50 | `MAX_STORED_PER_CONN` |
| Packet connections in output | top 40 by count | `top_conn_keys` slice |
| Ports per node in output | 30 | `sorted(...)[:30]` in serialisation |
