# Backlog

## Completed

- [x] OT Map: Fix undefined CSS variables `--bg1` / `--text1` (caused white patch in dark mode)
- [x] OT Map: Add D3 zoom + pan (Ctrl+scroll to zoom, drag to pan, +/−/⊡ toolbar buttons)
- [x] OT Map: ResponsiveObserver — SVG re-renders on container resize and detail-panel close
- [x] OT Map: Replace native SVG `<title>` tooltips with styled `#tooltip` div
- [x] OT Map: Highlight connected edges and dim unconnected on node hover
- [x] OT Map: Traffic-weighted edges — stroke width scales with `packet_count` (log scale)
- [x] OT Map: Anomaly callouts — `!` badge on nodes from `anomalyNodeIps`, lane tint for high-severity
- [x] OT Map: Legend — zone colour swatches, risk-level dots, bridge ring, edge type samples
- [x] OT Map: Risk annotation panel positioned near clicked node (viewport-clamped)
- [x] OT Map: Edit-mode hint bar with instructions; dismiss button; hint bar hidden by default
- [x] OT Map: Distinguish cross-zone (security boundary) vs cross-level (same zone) stats chips
- [x] OT Map: Suppress empty Unclassified zone from rendering
- [x] OT Map: Respect sidebar `activeTypes` filter; "filtered" chip when active
- [x] OT Map: Purdue level tooltips on lane label text elements
- [x] OT Map: `alert()` in Add Device replaced with inline `#ot-am-error` element
- [x] Backend: `purdue_level_py()` uses OT evidence (ot_role, modbus_unit_ids, dnp3_addresses) to demote L4→L3
- [x] Backend: `merge_results()` now outputs `purdue_level` for merged nodes
- [x] Frontend: `purdueLevel()` mirrors OT evidence demotion logic
- [x] OT Map: Public Internet zone (L6) — all non-RFC1918 IPs automatically placed in a top "Public Internet" lane; no GeoIP database required; zone suppressed when only private IPs present; OT→Internet edges flagged as critical cross-zone
- [x] UI: "Clear all filters" button — one click to reset protocols + host types + search back to defaults
- [x] UI: Zero-results feedback — inline message when search/filter combination hides all nodes
- [x] UI: Toast notifications — replaced all `alert()` calls with auto-dismissing toasts (4 s)
- [x] UI: Active filter count badge on Protocols / Host Types section headers
- [x] UI: Fit-to-visible after filtering — auto-zoom to visible node set
- [x] Performance: Progress bar during large PCAP parsing (streaming status instead of blank spinner)
- [x] Performance: Virtual scrolling in connection table and packet inspector (windowed rendering)
- [x] Performance: Anomaly deduplication summary — collapses repeated same-source anomalies into one entry
- [x] Performance: Replace `PcapReader` with `RawPcapReader` + manual byte parsing in `analyze_pcap()` hot loop (~30× speedup; 150K-packet capture: ~44s → ~1.5s)

## Navigation & Discoverability

- [ ] Collapsible sidebar — toggle arrow to collapse the 240 px sidebar to a narrow icon rail
- [ ] Keyboard shortcuts — F = fit graph, 1–4 = switch views, / = focus search, Escape = close panels; `?` overlay lists all shortcuts
- [ ] Expanded right-click context menu — Isolate node, Copy IP, Highlight anomalies, Open in Table view
- [ ] Breadcrumb / back button when jumping from anomaly sidebar → node → packet inspector
- [ ] View-specific empty states for DNS Map and OT Map before upload (illustrated placeholder)

## Graph View

- [ ] Node pinning toggle — push-pin icon to permanently lock position (d.fx / d.fy)
- [ ] Minimap — overview thumbnail (bottom-left) with viewport rectangle; essential for large captures
- [ ] Isolate mode — show only selected node + direct neighbours; second click restores
- [ ] Edge label on hover — inline packet count label on hovered edge (more glanceable than tooltip)
- [ ] Cluster expand / collapse — clicking cluster centre collapses all nodes of that type into one summary node

## Packet Inspector & Detail Panel

- [ ] Protocol-coloured hex dump — byte regions highlighted by layer (Ethernet / IP / TCP / payload)
- [ ] Copy buttons next to IP addresses, hex strings, and field values in detail panel
- [ ] Floating inspector mode — detach packet inspector into a resizable floating panel
- [ ] Search within packet list — filter input above packet table to narrow by IP, protocol, or info string

## Timeline

- [ ] Brush selection on minimap — click-drag to select a time window (Wireshark mental model)
- [ ] Playback speed control — 0.5×, 1×, 2×, 5× selector next to the play button
- [ ] Timestamp format toggle — switch between absolute (HH:MM:SS) and relative (seconds from first packet)

## Polish & Accessibility

- [ ] Persistent filter state — save last-used filter configuration in localStorage
- [ ] Light / dark mode toggle (~30 CSS variable overrides)
- [ ] Stats bar sparklines — tiny inline bar charts next to Hosts / Connections / Packets showing distribution
- [ ] Colour-blind safe palette option — deuteranopia-safe scheme (blues / oranges + pattern fills) toggle

## Bigger Ideas

- [ ] PCAP diff / comparison mode — upload two files and highlight added hosts, connections, anomalies
- [ ] Saved filter presets — name and save a filter combination for one-click recall
- [ ] Inline anomaly explanation panel — contextual explanation of what each anomaly means and why it's suspicious
- [ ] Dashboard / summary view (5th view) — card-based overview: top talkers, protocol breakdown donut, anomaly severity bar, busiest connections

## Completed (Enrichments)

- [x] Backend: DNS tunneling detection — `dns_tunneling_suspected` anomaly using three signals: high-entropy subdomain labels (>24 chars, >4.5 bits), abnormally long average query names (>60 chars), or unique-subdomain flood (>20 labels under same parent). 5 unit tests added.
- [x] Backend: Per-host risk score (0–100) — composite of anomaly severity, cross-zone egress (+15), suspicious port usage (capped +20), and OT write targeting (+10); emitted as `risk_score` on every node, propagated through `merge_results` (max of captures).
- [x] Frontend: Risk score badge on graph nodes (colored ring with number: gray <40, yellow 40–69, red ≥70); risk line in node tooltip; risk badge row in detail panel.
- [x] Backend: TLS ClientHello parsing — `parse_tls_client_hello()` extracts SNI (cleartext server name) and computes JA3/MD5 fingerprint from cipher suites + extensions + elliptic curves; stored per host as `tls_sni` / `tls_ja3`; propagated through `merge_results`.
- [x] Backend: `unusual_ja3` anomaly — fires when a host's JA3 matches a bundled known-bad fingerprint list (Metasploit, Cobalt Strike, Dridex, Emotet, Trickbot, AsyncRAT, QakBot, IcedID).
- [x] Frontend: TLS SNI list shown in detail panel and node tooltip; JA3 hashes shown with threat label and red color when matching known-bad; 8 unit tests added.

## Known Issues

- OT Map: PNG export exports the current zoom/pan view; consider a "fit-to-full" export option
- OT Map: Drag-to-reclassify ghost circle may flicker at extreme zoom levels
- General: GeoIP lookup is optional and silently skipped if MMDB absent; consider a warning banner
- General: Test coverage for `analyze_pcap` and `merge_results` is thin — add integration tests with sample PCAPs

- [x] Feature #4: TCP Follow Stream — "Stream" tab in packet inspector; sorts packets by time, groups by direction (client=blue, server=green), decodes hex payload to ASCII with non-printables as `.`; tab hidden when no payloads captured

## Completed (Bug Fixes)

- [x] Backend: IPv6 packet inspector crash — packet-inspector block unconditionally accessed `pkt[IP]`; now correctly branches `IP in pkt` / `IPv6 in pkt` and emits IPv6 header fields
- [x] Backend: CoAP option parser out-of-bounds — missing `idx >= len` guards before extended delta/length field reads; fixed with bounds checks
- [x] Backend: Port-scan false positives — bidirectional `src_dst_ports` attribution caused servers with many clients to be flagged; now only attributes ports to the connection's smaller-IP key
- [x] Backend: Purdue level returned -1 for Router, IoT Gateway, DNS Server, and 15 other common host types; added them to `_PURDUE_L4_TYPES` / `_PURDUE_L1_TYPES`
- [x] Frontend: `fetch("/upload")` did not check `resp.ok` before calling `.json()` — HTTP errors (4xx/5xx) showed a confusing parse error instead of the server message
- [x] Frontend: 26 protocols in PORT_MAP had no PROTO_COLORS entry and rendered as flat gray (NNTP, NetBIOS-*, LDAP/LDAPS, Docker, K8s-API, VNC, WinRM, IKE/IPsec, OpenVPN, Metasploit, etc.)
- [x] Frontend: DHCP Client, Discovery, and News Server host types had no HOST_COLORS entry and rendered as default gray
- [x] Frontend: OT filter toggle button (`#ot-filter-btn`) was wired in JS but missing from `index.html`; `otFilterAll` state was never togglable — added button to OT toolbar
- [x] Frontend: `d.dns_names[0]` in detail panel had no null guard; now `(d.dns_names && d.dns_names[0])`
- [x] CSS: `#ot-legend` rule incorrectly removed as "dead code" — element is created dynamically by JS; restored with `display: flex; flex-wrap: wrap` so legend items flow horizontally instead of stacking as block rows (~200 px tall)
- [x] OT Map: Matrix view color key — replaced plain-text legend note with inline SVG color swatches for each OT protocol (Modbus/DNP3/S7comm/EtherNet/IP/IEC-104/BACnet/CoAP/MQTT)
- [x] Tests: Added 8 unit tests for `parse_enip` (register session, read/write tag, error status, malformed input)
