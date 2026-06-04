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
- [x] VLAN: Full 802.1Q + 802.1ad QinQ parsing (VID, PCP, DEI); per-host and per-edge tracking; VLAN filter in sidebar; VLAN section in host detail panel; VLANs stat in header; 4 new anomaly rules (hopping, native leak, QinQ, cross-segment OT); dedicated VLAN Graph view (VLANs as super-nodes, hosts clustered inside, cross-VLAN traffic highlighted in red)
- [x] VLAN graph overhaul: multi-VLAN host membership (hopping hosts sit between segments); generalized cross-VLAN edge builder (all src×dst VLAN pairs); rich node decorations via shared `appendNodeDecorations` helper (anomaly rings, risk/cred glyphs, host icons, risk badges); shared tooltip helpers; neighbor highlighting + selection state; super-node click → VLAN detail panel (PCP dist, QinQ, cross-VLAN partners, member host list); stats bar (cross-VLAN flows/bytes, untagged/hopping counts); legend entries for cross-VLAN edge and untagged; hash-based `vlanColor` (no palette collisions)
- [x] IPv4/IPv6 filtering: `ip_version` per node + `ip_versions`/`has_untagged`/`ipv4_count`/`ipv6_count` in stats (both `analyze_pcap` and `merge_results`); IP Version sidebar filter (shown only when both present); `applyFilters` and table filter honour it; IPv6 dashed-stroke node distinction; header IPv6 adoption stat

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
- [x] Playback speed control — 0.5×, 1×, 2×, 5× selector next to the play button
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

## VLAN Follow-ups

- [ ] Per-VLAN bandwidth chart — bar chart of bytes/packets per VLAN in the VLAN view
- [ ] VLAN timeline — filter the main graph timeline by VLAN segment
- [ ] VLAN export — add vlans column to connections CSV export

## Completed (Enrichments)

- [x] Backend: DNS tunneling detection — `dns_tunneling_suspected` anomaly using three signals: high-entropy subdomain labels (>24 chars, >4.5 bits), abnormally long average query names (>60 chars), or unique-subdomain flood (>20 labels under same parent). 5 unit tests added.
- [x] Backend: Per-host risk score (0–100) — composite of anomaly severity, cross-zone egress (+15), suspicious port usage (capped +20), and OT write targeting (+10); emitted as `risk_score` on every node, propagated through `merge_results` (max of captures).
- [x] Frontend: Risk score badge on graph nodes (colored ring with number: gray <40, yellow 40–69, red ≥70); risk line in node tooltip; risk badge row in detail panel.
- [x] Backend: TLS ClientHello parsing — `parse_tls_client_hello()` extracts SNI (cleartext server name) and computes JA3/MD5 fingerprint from cipher suites + extensions + elliptic curves; stored per host as `tls_sni` / `tls_ja3`; propagated through `merge_results`.
- [x] Backend: `unusual_ja3` anomaly — fires when a host's JA3 matches a bundled known-bad fingerprint list (Metasploit, Cobalt Strike, Dridex, Emotet, Trickbot, AsyncRAT, QakBot, IcedID).
- [x] Frontend: TLS SNI list shown in detail panel and node tooltip; JA3 hashes shown with threat label and red color when matching known-bad; 8 unit tests added.

- [x] UI: Timeline keyboard shortcuts — Space toggles play/pause; ←/→ step the slider by one tick; shortcuts disabled when focus is inside an input/select
- [x] OT Map: Add Device validation — IP format check (reject non-IPv4) and Purdue level bounds check (−1 to 6) with inline error display; refactored duplicate error display into shared `_showErr` helper
- [x] DNS view: DNS tunnel suspect badges — hosts flagged by `dns_tunneling` anomaly now show an amber "DNS Tunnel?" badge in the DNS host list
- [x] Code: Packet inspector tab label parsing refactored — `_pktsForCurrentConn()` helper replaces three identical regex blocks in pkt-tab-pkts / pkt-tab-cmds / pkt-tab-stream click handlers

## Known Issues

- OT Map: PNG export exports the current zoom/pan view; consider a "fit-to-full" export option
- OT Map: Drag-to-reclassify ghost circle may flicker at extreme zoom levels
- General: GeoIP lookup is optional and silently skipped if MMDB absent; consider a warning banner
- General: Test coverage for `analyze_pcap` and `merge_results` is thin — add integration tests with sample PCAPs

- [x] Feature #4: TCP Follow Stream — "Stream" tab in packet inspector; sorts packets by time, groups by direction (client=blue, server=green), decodes hex payload to ASCII with non-printables as `.`; tab hidden when no payloads captured
- [x] Feature #5: Credentials extraction view — HTTP Basic auth, HTTP form POST, FTP USER/PASS, SMTP AUTH PLAIN/LOGIN, POP3 USER/PASS, IMAP LOGIN; sidebar panel with protocol filter + click-to-reveal passwords; capped at 500/capture, 2000/merge
- [x] Feature #10: Credentials feature improvements — fixed critical bug (extraction block was inside UDP branch, so TCP protocols were never extracted); added LDAP Simple Bind (BER-parsed), SNMP community strings (v1/v2c BER-parsed), Telnet login (IAC-stripped prompt/response state machine); fixed IMAP quoted-credential regex; fixed HTTP form POST to use parse_qs (handles &-in-password); added deduplication (same proto/src/dst/dport/user/pw kept once); password-reuse anomaly (high severity, fires when same password seen across 2+ protocols/destinations); key-icon on graph nodes with credentials; credentials section in node detail panel; "Export Credentials CSV" in export menu (includes passwords); 23 new unit tests
- [x] Feature #6: Unified OT command log — chronological global table of all Modbus/DNP3/S7comm/EtherNet/IP/IEC-104/BACnet commands; 5th view tab ("OT Log"); filter by protocol + direction; color-coded read/write/error/diagnostic; 5000 cmd cap per capture
- [x] Feature #7: HTTP file transfer detection — detects HTTP server responses with interesting Content-Type (application/*, image/*, audio/*, video/*, text/csv, text/xml) or Content-Disposition: attachment; extracts filename, MIME type, Content-Length, SHA-256 of body bytes; sidebar "File Transfers" panel with hash; capped at 200/capture, 500/merge (deduped by SHA-256); 12 unit tests added
- [x] Feature #8: PCAP baseline diff — "Set Baseline" header button saves current graphData; uploading a second PCAP reveals "⊕ Diff" view tab; three-column diff shows new/disappeared hosts, new connections (with protocols), and new anomalies vs baseline; frontend-only, no server round-trip
- [x] Feature #9: Markdown audit report — "Export Audit Report" in export dropdown; generates a `.md` file client-side with: capture summary table, top-10 hosts by risk score, anomalies grouped by severity, OT inventory by Purdue level, TLS/SNI observations, DNS tunneling suspects, captured credentials table, file transfers table, OT write operations; no server round-trip

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
- [x] OT Matrix: Sticky row/column headers via CSS Grid (3-SVG layout: cols/rows/cells); headers remain visible while scrolling large captures
- [x] OT Matrix: Click trap removed — cell click now navigates to graph view + opens packet inspector for that connection; tooltip shows "Click to inspect packets"
- [x] OT Matrix: Row/column hover highlight — crosshair bands highlight the active row and column; hovered label turns bright white
- [x] OT Matrix: Group nodes by zone (OT → DMZ → IT → Internet) before sorting by connection count; faint separator lines at zone boundaries on both axes
- [x] OT Matrix: Middle-ellipsis label truncation with full-name `<title>` tooltip on hover (previously cut the front of long hostnames)
- [x] OT Matrix: Empty state shows friendly message when no devices match current filters (was silent)
- [x] OT Matrix: Re-renders automatically when sidebar filters change (was stale until manually toggled)
- [x] OT Matrix: PNG export targets the matrix SVGs when in matrix mode (previously always exported the hidden Purdue map)
- [x] OT Matrix: "Showing top 40 of N" hint rendered in legend area when capture has >40 devices
- [x] OT Matrix: Tooltip arrow changed from → to ↔ (edges are undirected)
- [x] OT Matrix: Anomaly border stroke-width increased to 2 on cross-zone+anomaly cells for visibility
- [x] OT Matrix: Diagonal cells rendered as visually inert dark rects (no hover/click)
- [x] Bug fix: pcapng files crashed `analyze_pcap` with `'PacketMetadataNg' object has no attribute 'sec'` — fixed timestamp extraction to use `tshigh`/`tslow`/`tsresol` for pcapng vs `sec`/`usec` for pcap (`app.py:1867`)
- [x] Tests: Added `tests/test_pcapng.py` — 4 integration tests covering pcapng parse, pcap/pcapng parity, and mixed-format merge

## Robustness Review — MED/LOW Deferred Items

Items surfaced in the 2026-05-17 robustness review (`REVIEW.md`) that were not addressed in `feature/robustness-fixes` (all HIGH items are fixed). Sorted roughly by risk.

- [ ] **E3** — `except Exception: pass` in packet-store enrichment loop drops errors silently; surface a `parse_errors` count in `stats`
- [ ] **E4** — Non-JSON 502 responses from `/upload` show a cryptic SyntaxError in the UI; wrap `resp.json()` in a try and show raw response head
- [ ] **E5** — `FileReader` in session-load has no `onerror` handler; corrupt file silently does nothing
- [ ] **U4** — Tempfile path appended to `tmp_paths` *after* `f.save()`; if save raises, the tempfile leaks — reverse the order
- [ ] **U5** — `secure_filename` on a unicode-only name returns empty string; suffix becomes the full name → whitelist suffix to `.pcap/.pcapng/.cap`
- [ ] **P3** — BACnet NPDU routing-field truncation falls through instead of returning `None`; can produce garbage `apdu_offset`
- [ ] **P4** — IEC104 `apdu_len = payload_bytes[1]` never validated against `len(payload_bytes)`
- [ ] **X5** — `c.dport` in nodeCreds block interpolated raw into innerHTML (`':'+c.dport`)
- [ ] **X6** — `d.modbus_unit_ids.join()` / `d.dnp3_addresses.join()` inserted unescaped into innerHTML
- [ ] **X7** — OT-edge tooltip (`app.js:2930`): `e.source`/`e.target` raw
- [ ] **X8** — `resolvedIps.join(", ")` inserted raw into innerHTML in DNS view
- [ ] **X9** — `d.open_ports.slice(0,20).join(", ")` inserted raw
- [ ] **N5** — `f.sha256.slice(0,16)` crashes if backend omits `sha256` field
- [ ] **N6** — `s7.function_code.toString(16)` crashes if backend sends `null` (not `undefined`)
- [ ] **L2** — D3 simulation tick/end handlers not nulled out before `stop()` — old closures fire briefly
- [ ] **L3** — `setTimeout(() => zoomFit(), 2500)` not cleared on re-upload; stale fit fires on new graph
- [ ] **PF3** — `openPktInspectorForHost` concatenates all packets and sorts in main thread (150k packets → jank)
- [ ] **PF4** — `renderConnTable` re-sorts entire edges array on each filter toggle
- [ ] **S2** — No CSRF protection on `/upload` POST (low risk on localhost; medium when `--public`)
- [ ] **S3** — `_get_geoip_reader` double-init not protected by a lock (thread safety)
- [ ] **S4** — No `app.secret_key` from env var; any future session/flash use will break on restart
- [ ] **T5** — No `tests/conftest.py`; packet-builder helpers duplicated across test files
- [ ] **D1** — `geoip2` version not pinned in requirements.txt
- [ ] **H3** — README does not warn that `--public` exposes a Werkzeug dev server (see also `--public` banner added in B6)
- [ ] **General** — No `prompt()` modal replacement (blocks page, disabled by Firefox after 2 dialogs); affects OT risk note input and annotation input
