# PCAP Network Visualizer

An interactive web-based tool for visualizing network packet captures. Upload a `.pcap`, `.pcapng`, or `.cap` file and explore your network as a live force-directed graph — with host classification, protocol detection, OS fingerprinting, and DNS resolution.

![Python](https://img.shields.io/badge/python-3.8%2B-blue) ![Flask](https://img.shields.io/badge/flask-2.3%2B-lightgrey) ![License](https://img.shields.io/badge/license-MIT-green)

## Features

- **Interactive graph** — D3.js v7 force simulation; drag, zoom, and pan
- **Host classification** — Router, Web Server, DNS Server, Windows Host, etc.
- **Protocol detection** — 50+ protocols identified by port (HTTP, SSH, DNS, RDP, MySQL, …)
- **OS fingerprinting** — TTL-based heuristic (Linux/Unix, Windows, Network Device)
- **MAC vendor lookup** — Identifies VMware, Cisco, Apple, Raspberry Pi, and more
- **DNS name resolution** — Extracts hostnames from captured DNS traffic
- **Filtering** — Filter graph by protocol or host type via sidebar checkboxes
- **Search** — Find nodes by IP address or hostname
- **Detail panel** — Click any node to see full host details (ports, services, traffic, DNS queries)
- **Large capture support** — Streams up to 150,000 packets without loading everything into memory

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

Upload a capture file (`.pcap`, `.pcapng`, or `.cap`, up to 200 MB) and the graph will render automatically.

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
| `MAX_CONTENT_LENGTH` | 200 MB | Maximum upload file size |
| `MAX_PACKETS` | 150,000 | Packets processed per file |
| Port | 5000 | HTTP port (`app.py` line 438) |

To change the port, edit the last line of `app.py`:

```python
app.run(debug=True, host="0.0.0.0", port=5000)
```

## Troubleshooting

**`scapy` import error** — Make sure you installed dependencies inside the correct Python environment (or virtualenv).

**Permission denied reading pcap** — Some systems require root to read certain capture files. Try `sudo python app.py`.

**Graph is empty after upload** — The file may contain only non-IP traffic (e.g. pure Bluetooth or USB captures). The tool currently supports IPv4 and ARP packets.

**Very large files are slow** — Only the first 150,000 packets are processed. For faster results, pre-filter with `tcpdump`:
```bash
tcpdump -r big.pcap -w filtered.pcap 'tcp or udp'
```

## License

MIT
