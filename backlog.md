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
- [x] VLAN exports: two new Export dropdown items (Export VLAN Inventory CSV, Export VLAN Traffic CSV); `exportVlanInventoryCsv()` emits one row per (VLAN, host) pair with 14 columns; `exportVlanTrafficCsv()` emits flat table with Source/Dest VLAN columns and Cross-VLAN flag; audit report gains "VLAN Device Inventory" section (per-VLAN host tables) and "IP-to-IP Traffic by VLAN" section (grouped by VLAN, capped at 100/group), plus VLANs-detected row in Capture Summary

## Navigation & Discoverability

- [x] Collapsible sidebar — toggle arrow (`‹`/`›`) collapses sidebar to 32 px; state persisted in localStorage
- [x] Keyboard shortcuts — F = fit graph, 1–8 = switch views, / = focus search, Esc = close; `?` overlay lists all shortcuts
- [x] Expanded right-click context menu — Highlight Anomalies (fades non-anomaly nodes), Open in Table (switches view and pre-filters to that node's IP)
- [x] Breadcrumb / back button when jumping from anomaly sidebar → node → packet inspector — `showDetailPanel` accepts `navCtx`; breadcrumb bar shows "Anomalies › <type> › <ip>" with back-arrow
- [x] View-specific empty states for DNS Map and OT Map before upload (illustrated placeholder) — `#dns-empty-state` / `#ot-empty-state` divs shown via `setView()` when no data loaded

## Graph View

- [x] Node pinning — select a node and press P to lock position; dashed yellow ring; drag updates pin; Unpin All in right-click menu
- [x] Minimap — 150×100 overview thumbnail (bottom-right) with viewport rectangle; drag to pan; live sync with simulation
- [x] Isolate mode — double-click a node to show only it + direct neighbours; double-click again to restore
- [x] Edge label on hover — inline packet count label at edge midpoint; hidden in canvas mode (>150 nodes)
- [x] Cluster expand / collapse — ⊕ button in graph controls enters cluster mode; click a host-type label in sidebar to collapse that type into a centroid chip overlay; click chip to expand; mode indicator and localStorage-free toggle

## Packet Inspector & Detail Panel

- [x] Protocol-coloured hex dump — byte regions highlighted by layer (Ethernet / IP / TCP / payload); backend emits start/end byte offsets per layer; frontend builds per-byte color array and wraps hex bytes in colored spans
- [x] Copy buttons next to IP addresses, hostnames, JA3 fingerprints, and SHA-256 hashes in detail panel and files sidebar
- [x] Floating inspector mode — ⧉ button in packet inspector header detaches to fixed overlay; draggable via resize handle; ⊡ button re-docks; docking restores graph-wrap layout
- [x] Search within packet list — live-filter input above packet table; shows `N / M` count badge; clears on new connection open

## Timeline

- [x] Brush selection on timeline — two-handle range brush replaces single slider; select an arbitrary time window; play advances the window; ←/→ shift the window; blue selection highlight overlay
- [x] Playback speed control — 0.5×, 1×, 2×, 5× selector next to the play button
- [x] Timestamp format toggle — "abs" button switches between UTC HH:MM:SS and relative +Ns format

## Polish & Accessibility

- [x] Persistent filter state — last-used protocol/host-type selections saved to localStorage; restored on next load
- [x] Light / dark mode toggle — ☀/☾ button in header; CSS variable overrides for full dark/light switch; persisted in localStorage; FOUC-prevention inline script
- [x] Stats bar sparklines — 48×12 px inline SVG bar chart (60 bins) next to Packets stat; shows packet density over capture time
- [x] Colour-blind safe palette option — ◑ button; deuteranopia-safe overrides (greens→teal, reds→orange); re-colors all graph nodes + filter swatches; persisted in localStorage

## Bigger Ideas

- [x] PCAP diff / comparison mode — upload two files and highlight added hosts, connections, anomalies
- [x] Saved filter presets — name and save a filter combination for one-click recall; presets stored in localStorage; chip list in sidebar with delete buttons; auto-shown when at least one preset exists
- [x] Inline anomaly explanation panel — ℹ button on every anomaly badge expands a "What / Why / Steps" explanation covering all ~30 anomaly types; toggles closed with a second click
- [x] Dashboard / summary view — 8th view tab (⊛ Dashboard); 5 summary cards (hosts/connections/packets/anomalies/protocols); top-10 risk-score horizontal bar chart; protocol distribution bars; anomaly severity chips (High/Med/Low/Info counts); busiest-connections list; clicking a risk-bar row jumps to graph and highlights the node; key shortcut: 8

## VLAN Follow-ups

- [x] Per-VLAN bandwidth chart / VLAN timeline — timeline minimap now shows stacked per-VLAN byte bars when VLAN data is present; bars are colored by VLAN using the same vlanColor() palette; falls back to plain density bars for non-VLAN captures
- [x] VLAN export — covered by Export VLAN Traffic CSV (includes Source/Dest VLAN columns and Cross-VLAN flag)

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
- [x] Diff view enhancement — host diff now detects type changes, risk-score delta >20, new protocols, new open ports, each shown as a descriptive badge; connection diff adds a "changed traffic" row when byte/packet count ratio is >2× or <0.5× between captures
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

- [x] **E3** — surface `parse_errors` count in `stats`; shown as info toast on upload
- [x] **E4** — `fetch /upload` wraps `.json()` in try/catch; falls back to `resp.text()` for non-JSON error bodies
- [x] **E5** — `FileReader.onerror` handler added to both file-load usages; shows toast on failure
- [x] **U4** — Tempfile path appended to `tmp_paths` before `f.save()` so cleanup always runs
- [x] **U5** — `secure_filename` on unicode-only names returns empty string; whitelist suffix to `.pcap/.pcapng/.cap`
- [x] **P3** — BACnet NPDU routing-field bounds check tightened; falls through with `return None` on truncation
- [x] **P4** — IEC104 `apdu_len` validated against `len(payload_bytes)` before use
- [x] **X5** — `c.dport` in nodeCreds block escaped via `escHtml()`
- [x] **X6** — `modbus_unit_ids` / `dnp3_addresses` escaped with `.map(escHtml).join(", ")`
- [x] **X7** — OT-edge tooltip source/target values escaped
- [x] **X8** — `resolvedIps.map(escHtml).join(", ")` in DNS view
- [x] **X9** — `open_ports.slice(0,20).map(escHtml).join(", ")`
- [x] **N5** — `(f.sha256 || '').slice(0,16)` guards missing sha256 field
- [x] **N6** — `s7.function_code != null` (loose equality catches both null and undefined)
- [x] **L2** — Simulation tick/end handlers nulled out before `stop()` in `renderGraph` and `buildSimulation`
- [x] **L3** — `_zoomFitTimer` cleared on re-upload; no stale zoomFit after new graph load
- [x] **PF4** — `_getSortedEdges()` cache with fingerprint string avoids re-sorting on every filter toggle
- [x] **S3** — `_geoip_lock` already in place; double-checked and confirmed thread-safe
- [x] **S4** — `app.secret_key = os.environ.get("PCAPVIS_SECRET_KEY", os.urandom(32))`
- [x] **T5** — `tests/conftest.py` created with shared fixtures and packet-builder helpers
- [x] **D1** — `geoip2>=4.0.0,<5` pinned in requirements.txt
- [ ] **PF3** — `openPktInspectorForHost` concatenates all packets and sorts in main thread (150k packets → jank)
- [ ] **S2** — No CSRF protection on `/upload` POST (low risk on localhost; medium when `--public`)
- [ ] **H3** — README does not warn that `--public` exposes a Werkzeug dev server
- [ ] **General** — No `prompt()` modal replacement (blocks page, disabled by Firefox after 2 dialogs); affects OT risk note input and annotation input
