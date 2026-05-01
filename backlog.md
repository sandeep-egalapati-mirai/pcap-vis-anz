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

## Known Issues / Ideas

- OT Map: PNG export exports the current zoom/pan view; consider a "fit-to-full" export option
- OT Map: Drag-to-reclassify ghost circle may flicker at extreme zoom levels
- OT Map: Add a "Show all" toggle button to `#ot-toolbar` to override `activeTypes` filter (groundwork wired, button not yet in HTML)
- General: GeoIP lookup is optional and silently skipped if MMDB absent; consider a warning banner
- General: Test coverage for `analyze_pcap` and `merge_results` is thin — add integration tests with sample PCAPs
