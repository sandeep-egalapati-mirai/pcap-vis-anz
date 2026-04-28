# PCAP Network Visualizer

An interactive web-based tool for visualizing network packet captures. Upload a `.pcap`, `.pcapng`, or `.cap` file and explore your network as a live force-directed graph — with host classification, protocol detection, OS fingerprinting, and DNS resolution.

![Python](https://img.shields.io/badge/python-3.8%2B-blue) ![Flask](https://img.shields.io/badge/flask-2.3%2B-lightgrey) ![License](https://img.shields.io/badge/license-MIT-green)

## Features

- **Interactive graph** — D3.js v7 force simulation with Force, Radial, and Cluster layout modes; drag, zoom, and pan
- **Host classification** — 38 host types: Router, PLC, IP Camera, Web Server, DNS Server, Windows Host, and more
- **Protocol detection** — 80+ protocols identified by port (HTTP, SSH, DNS, RDP, MySQL, Modbus, MQTT, CoAP, …)
- **IPv4 and IPv6 support** — both address families tracked; private ranges correctly classified
- **OS fingerprinting** — TTL / hop-limit heuristic (Linux/Unix, Windows, Network Device)
- **MAC vendor lookup** — OUI lookup covering IT, OT, and IoT vendors (VMware, Cisco, Siemens, Amazon Echo, …)
- **DNS name resolution** — Extracts hostnames and query logs from captured DNS traffic
- **Filtering** — Filter graph by protocol or host type via sidebar checkboxes
- **Search** — Find nodes by IP address or hostname
- **Detail panel** — Click any node to see host details (ports, services, traffic stats, DNS queries, anomalies, conversations)
- **Three views** — Graph (network map), Table (sortable connection list), DNS Map (query explorer)
- **Timeline** — Scrub or auto-play packet activity over time; packet-density minimap
- **Packet inspector** — Click any edge or node to open a Wireshark-style panel showing per-packet protocol trees and hex dumps
- **Exports** — PNG graph screenshot, connections CSV, anomalies CSV
- **Session save / load** — Export full analysis to JSON and reload without re-uploading the capture file
- **Node annotations** — Right-click any node to attach a persistent note (stored in browser localStorage)
- **Anomaly detection** — 18 detection rules across general network, OT/ICS, and IoT threat categories
- **Large capture support** — Streams up to 1,000,000 packets without loading into memory (up to 1 GB upload)

## Anomaly Detection

18 detection rules fire automatically after analysis:

**General network**
- Port scan — single source contacting >5 IPs across >15 unique ports
- Cleartext credentials — FTP or Telnet traffic with payload
- Beaconing — connection with highly regular inter-packet timing (coefficient of variation < 0.2)
- Data exfiltration — host sending >10 MB to a non-private IP
- Suspicious ports — known C2/hack-tool ports (4444, 1337, 31337, 6666, 6667)

**OT / ICS**
- Modbus write commands (FC 5/6/15/16) — unauthorized PLC writes
- DNP3 control/operate commands (Direct Operate, Select-Before-Operate, Cold/Warm Restart)
- S7comm Write Variable and PLC Stop / PI Service commands
- EtherNet/IP CIP Write Tag / Set Attribute operations
- IEC 60870-5-104 command activation (Type IDs 45–50 with COT=Activation)
- BACnet writeProperty / reinitializeDevice / deviceCommunicationControl
- OT device communicating with an internet host
- Cleartext OT protocols (Modbus, DNP3, S7, BACnet have no encryption)

**IoT**
- Cleartext MQTT (port 1883) — credentials and sensor data unencrypted
- Telnet access to an IoT device — classic Mirai botnet vector
- IP Camera sending data to an external IP — unauthorized stream or C2
- TR-069 (port 7547) — remote management protocol frequently exploited

All anomalies are shown in the sidebar and on the node detail panel; affected nodes pulse with a coloured ring (red = high, yellow = medium).

## OT/ICS Protocol Support

The visualizer detects and classifies industrial control system devices and protocols:

**Supported protocols:** Modbus TCP, EtherNet/IP, Siemens S7comm, DNP3, IEC 60870-5-104, BACnet, OPC-UA, MQTT, PROFINET, HART-IP, GE SRTP, OMRON FINS, Emerson DeltaV

**OT device types:** PLC, RTU, IED, HMI, SCADA Server, DCS, Historian, Engineering Workstation, Building Controller, IoT Gateway, Field Device

**OT vendor fingerprinting:** Rockwell Automation, Siemens, Schneider Electric, ABB, Emerson, GE Digital, Honeywell, Yokogawa, WAGO, Phoenix Contact, Mitsubishi Electric, Omron, Beckhoff, Moxa

**OT-specific anomaly detection:**
- Modbus write commands (FC 5/6/15/16) — unauthorized PLC writes
- DNP3 control/operate commands (Direct Operate, Select-Before-Operate, Cold/Warm Restart)
- S7comm Write Variable, PLC Stop, and PI Service (Start/Stop) commands
- EtherNet/IP CIP Write Tag / Set Attribute operations
- IEC 60870-5-104 command activation (Type IDs 45–50 with COT=Activation)
- BACnet writeProperty / reinitializeDevice / deviceCommunicationControl
- OT device exposed to internet traffic
- Cleartext OT protocols (Modbus, DNP3, S7, BACnet have no encryption)

**Protocol deep inspection (packet detail panel):**
- **Modbus TCP**: Function codes, unit ID, register addresses; write commands flagged in red
- **DNP3**: Link-layer src/dst addresses, application function code, direction (master↔RTU)
- **S7comm**: ROSCTR message type, PDU reference, function code (over TPKT+COTP)
- **EtherNet/IP**: Encapsulation command, session handle, CIP service code and name
- **IEC 60870-5-104**: Frame type (I/S/U), ASDU type ID, Cause of Transmission (COT), common address
- **BACnet/IP**: BVLC function, APDU PDU type, confirmed/unconfirmed service name

## IoT Device Support

**Supported protocols:** MQTT, MQTT-TLS, CoAP, CoAP-DTLS, AMQP, AMQPS, XMPP, RTSP, Matter, WS-Discovery, TR-069, Tuya-IoT, Hikvision, Dahua, DLMS (smart meters)

**IoT device types:** IP Camera, Smart Home Hub, Smart Meter, IoT Sensor, Smart Speaker, IoT Gateway, CPE Device

**IoT vendor fingerprinting (MAC OUI):** Amazon Echo, Google Home/Nest, Philips Hue, Samsung SmartThings, Ring, Wyze, TP-Link Kasa, Tuya Smart, Shelly, Particle, Fitbit, LIFX, August Smart Lock

**IoT-specific anomaly detection:**
- Cleartext MQTT (port 1883) — credentials and sensor data unencrypted
- Telnet access to IoT devices — classic Mirai botnet attack vector
- IP Camera sending data to external IPs — unauthorized streams or C2
- TR-069 (port 7547) — remote management protocol frequently exploited

**Protocol deep inspection:**
- **MQTT**: Decodes message type (CONNECT/PUBLISH/SUBSCRIBE), client ID, topic names, payload preview, QoS level, credential presence
- **CoAP**: Decodes message type (CON/NON/ACK), method/response code, URI path, payload preview

## Requirements

- Python 3.8+
- pip

## Installation

### 1. Clone the repository

```bash
git clone https://github.com/esandeepchoudary/pcap-vis-anz.git
cd pcap-vis-anz
```

### 2. (Optional) Create a virtual environment

```bash
python3 -m venv venv
source venv/bin/activate        # Linux / macOS
venv\Scripts\activate           # Windows
```

### 3. Install dependencies

```bash
pip install -r requirements.txt
```

> **Note for Kali / Debian systems** — if pip complains about externally managed environments, add `--break-system-packages`:
> ```bash
> pip install -r requirements.txt --break-system-packages
> ```

## Usage

```bash
python app.py
```

Then open your browser and go to:

```
http://localhost:5000
```

Upload a capture file (`.pcap`, `.pcapng`, or `.cap`, up to 1 GB) and the graph will render automatically.

## Capturing your own traffic

If you don't have a capture file handy, you can create one with `tcpdump` or Wireshark:

```bash
# Capture 60 seconds of traffic on any interface
sudo tcpdump -i any -w capture.pcap -G 60 -W 1

# Or capture on a specific interface
sudo tcpdump -i eth0 -w capture.pcap
```

Sample `.pcap` files are also available at [https://www.malware-traffic-analysis.net](https://www.malware-traffic-analysis.net) and the [Wireshark sample captures page](https://wiki.wireshark.org/SampleCaptures).

## Project Structure

```
pcap-vis-anz/
├── app.py                  # Flask backend + PCAP parser (scapy)
├── requirements.txt        # Python dependencies
├── templates/
│   └── index.html          # Single-page app shell
└── static/
    ├── css/style.css       # Dark GitHub-style theme
    └── js/app.js           # D3.js force graph + UI logic
```

## Configuration

| Setting | Default | Description |
|---|---|---|
| `MAX_CONTENT_LENGTH` | 1 GB | Maximum upload file size |
| `MAX_PACKETS` | 1,000,000 | Packets processed per file |
| `MAX_HOSTS` | 50,000 | Max unique hosts tracked per file |
| `MAX_STORED_PER_CONN` | 50 | Packets stored per connection for the inspector |
| Connections in inspector | top 40 | Connections with packet detail (by packet count) |
| Ports shown per node | 30 | Open ports listed in the detail panel |
| DNS names per node | 5 | Resolved hostnames shown in the detail panel |
| DNS queries per node | 10 | DNS queries shown in the detail panel |
| Port | 5000 | HTTP port (last line of `app.py`) |

To change the port, edit the last line of `app.py`:

```python
app.run(debug=False, host="127.0.0.1", port=5000)
```

## Security & self-containment

This tool is designed for **air-gapped / offline use**:

- D3.js v7 is bundled locally — no CDN requests
- CSS uses system fonts only — no Google Fonts
- The only outbound browser request is `POST /upload` to the same origin
- PNG export uses `blob:` URLs — no third-party image host

HTTP security headers are set on every response (`Content-Security-Policy`, `X-Content-Type-Options`, `X-Frame-Options`, `Referrer-Policy`). The app binds to `127.0.0.1` by default so it is not reachable from the network.

## Troubleshooting

**`scapy` import error** — Make sure you installed dependencies inside the correct Python environment (or virtualenv).

**Permission denied reading pcap** — Some systems require root to read certain capture files. Try `sudo python app.py`.

**Graph is empty after upload** — The file may contain only non-IP traffic (e.g. pure Bluetooth or USB captures). The tool supports IPv4, IPv6, and ARP packets.

**Very large files are slow** — Only the first 1,000,000 packets are processed. For faster results, pre-filter with `tcpdump`:
```bash
tcpdump -r big.pcap -w filtered.pcap 'tcp or udp'
```

## License

MIT
