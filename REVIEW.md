# Security & Robustness Review

**Date:** 2026-05-17  
**Scope:** Full-stack — `app.py`, `static/js/app.js`, `tests/`, `requirements.txt`  
**Auditors:** Three-agent automated review + manual verification  
**Branch:** `feature/robustness-fixes`

---

## Executive Summary

Five top risks found:

1. **No logging** — every `except Exception` in the backend silently drops the exception with no server-side trace. Real bugs are invisible until they cause user-facing breakage.
2. **XSS in multiple DOM injection sites** — PCAP-derived strings (IP addresses, protocol names, OT risk notes) are injected into `innerHTML` without `escHtml()` in the connection table, detail panel, OT tooltip, and DNS view.
3. **Upload DoS** — `ThreadPoolExecutor()` has no worker cap and no per-task timeout; a single malformed 1 GB PCAP can hang a thread indefinitely, and multiple concurrent uploads exhaust workers + memory.
4. **DNS loop unbounded** — scapy's DNS `an.payload` chain is iterated with `while an and hasattr(an, "type")` but crafted pointer loops can produce an infinite sequence via scapy's internal indirection.
5. **TLS JA3 shape inconsistency** — `app.js:1414` treats `tls_ja3[i]` as a bare string, while `app.js:4485` (audit report) treats it as an object `{hash: "..."}`. One of the two codepaths will fail at runtime on any capture with TLS.

Items labelled **HIGH** are fixed in this branch. **MED** and **LOW** items are added to `backlog.md`.

---

## Findings

### Category 1 — Error Handling & Logging

| ID | File:Line | Severity | Description | Fix |
|----|-----------|----------|-------------|-----|
| E1 | `app.py:22,317,336,525,649,782,843,924,1019,1163,2525,3011` | HIGH | No `logging` import; every `except Exception` silently drops errors with no server-side trace | Add `logger = logging.getLogger(__name__)` and `logger.warning(…, exc_info=True)` in catch blocks |
| E2 | `app.py:2528–2529` | HIGH | `except Exception as e: return {"error": f"…{e}"}` leaks filesystem path and internal exception text to the client | Log full traceback server-side; return generic `"Failed to parse PCAP"` to client |
| E3 | `app.py:2525` | MED | `except Exception: pass` in packet-store block silently drops packet enrichment for every malformed packet | Replace `pass` with counter; surface `parse_errors` count in `stats` |
| E4 | `app.js:351–367` | LOW | `uploadFiles` calls `resp.json()` without catching non-JSON responses (502 HTML returns SyntaxError with cryptic message) | Wrap `resp.json()` in its own try and surface `resp.text()` as diagnostic |
| E5 | `app.js:4615` | LOW | `FileReader` in session-load has no `onerror` handler; corrupt file silently does nothing | Add `reader.onerror` that shows an error toast |

### Category 2 — Input Validation & Upload DoS

| ID | File:Line | Severity | Description | Fix |
|----|-----------|----------|-------------|-----|
| U1 | `app.py:266–267` | HIGH | `allowed_file` checks extension only; rename any binary to `.pcap` and it's accepted | Peek first 4 bytes for magic signatures (`0xA1B2C3D4`, `0xD4C3B2A1`, `0x0A0D0D0A`) |
| U2 | `app.py:2982` | HIGH | `ThreadPoolExecutor()` uses default worker count (min 32, cpus+4); no per-task timeout — malicious PCAP hangs a thread indefinitely | Module-level `ThreadPoolExecutor(max_workers=4)`; wrap each task with `future.result(timeout=120)` |
| U3 | `app.py:2961` | HIGH | No limit on number of uploaded files; 1000 × 1 MB files exhaust disk + workers | Cap `len(files) > 10` → return 400 |
| U4 | `app.py:2977–2980` | MED | `NamedTemporaryFile` is created before being appended to `tmp_paths`; if `f.save()` raises, the tempfile leaks | Append `tmp.name` to `tmp_paths` *before* calling `f.save()` |
| U5 | `app.py:2976` | LOW | `secure_filename` on a unicode-only filename returns empty string; `rsplit(".",1)[-1]` then equals the full name, yielding an odd NamedTemporaryFile suffix | Whitelist suffix: only allow `.pcap`, `.pcapng`, `.cap` |

### Category 3 — Protocol Parser Safety

| ID | File:Line | Severity | Description | Fix |
|----|-----------|----------|-------------|-----|
| P1 | `app.py:342` | HIGH | `_ber_len` indexes `data[off]` with no bounds check; attacker-controlled offset can raise IndexError (swallowed) or corrupt offset arithmetic | Guard: `if off >= len(data): return 0, off` |
| P2 | `app.py:2104` | HIGH | DNS `an` chain iterated with `while an and hasattr(an, "type")` — crafted pointer loops in scapy's DNS layer create infinite traversal | Cap with `for _ in range(100):` |
| P3 | `app.py:952–959` | MED | BACnet NPDU routing-field parser skips over truncated payload but continues rather than returning `None`, leading to garbage `apdu_offset` | Add `return None` on truncation inside specifier blocks |
| P4 | `app.py:854` | LOW | IEC104 `apdu_len = payload_bytes[1]` parsed but never validated against `len(payload_bytes)` | Guard `if len(payload_bytes) < apdu_len + 2: return None` |
| P5 | `app.py:500–508` | LOW | MQTT remaining-length loop: guarded by `idx > 4` but `multiplier` overflows 32 bits for crafted values beyond 4 iterations (early exit prevents it in practice — low risk) | Document the guard explicitly |

### Category 4 — XSS & Unsafe DOM Injection

| ID | File:Line | Severity | Description | Fix |
|----|-----------|----------|-------------|-----|
| X1 | `app.js:2451–2456` | HIGH | `_buildConnTr`: `e.source`, `e.target`, `e.protocols.join()`, `e.ports.slice().join()` injected into `innerHTML` without `escHtml` | Wrap all four with `escHtml()` |
| X2 | `app.js:1543–1551` | HIGH | Detail-panel peer rows: `peer`, `proto`, `e.source`, `e.target` (including `td title`) injected raw | `escHtml()` all interpolated fields |
| X3 | `app.js:3072–3076` | HIGH | OT node tooltip: `n.ip`, `n.host_type`, `levelLabel`, `n.protocols[]`, `risk.note`, `risk.label` injected without escaping — `risk.note` is user-typed text | `escHtml()` every field |
| X4 | `app.js:3927` | HIGH | DNS tunnel-badge block injects `n.ip` raw into innerHTML | `escHtml(n.ip)` |
| X5 | `app.js:1453,1460,1465` | MED | `nodeCreds` block: `c.dport` interpolated raw (`':'+c.dport`) | `escHtml(String(c.dport))` |
| X6 | `app.js:1525,1528` | MED | `d.modbus_unit_ids.join()` and `d.dnp3_addresses.join()` inserted unescaped | Escape or convert to numeric assertion |
| X7 | `app.js:2930` | MED | OT-edge tooltip: `e.source`/`e.target` injected raw | `escHtml` both fields |
| X8 | `app.js:3960` | LOW | `resolvedIps.join(", ")` inserted raw into innerHTML | Escape each IP before join |
| X9 | `app.js:1392–1393` | LOW | `d.open_ports.slice(0,20).join(", ")` inserted raw | Escape defensively |

### Category 5 — Frontend Null/Undefined Safety

| ID | File:Line | Severity | Description | Fix |
|----|-----------|----------|-------------|-----|
| N1 | `app.js:382,389–395,511,515` | HIGH | `loadGraph` accesses `data.stats.truncated`, `data.stats.total_hosts`, `data.nodes`, `data.edges` without null guards; missing fields white-screen the app | Default-coalesce: `const stats = data.stats \|\| {}` etc. |
| N2 | `app.js:1290,1385,1390,1397,1402,1543` | HIGH | Detail panel reads `d.protocols.slice`, `d.services.length`, `d.open_ports.length`, `d.dns_names.length` without existence checks | `(d.protocols \|\| []).slice(…)` pattern throughout |
| N3 | `app.js:511,515` | HIGH | `graphData.edges.forEach(e => e.protocols.forEach(…))` — missing `protocols` on any edge crashes filter build | `(e.protocols \|\| []).forEach(…)` |
| N4 | `app.js:4485` | HIGH | TLS JA3 shape inconsistency: L1414 treats `tls_ja3[i]` as string (hash key), L4485 treats it as `{hash: "…"}` object — one path always crashes | Verify backend serialization; unify both consumers on the actual shape |
| N5 | `app.js:4538` | MED | `f.sha256.slice(0,16)` crashes if backend omits `sha256` field | `(f.sha256 \|\| "").slice(0,16)` |
| N6 | `app.js:2235` | LOW | `s7.function_code.toString(16)` crashes if backend sends `null` (only guarded against `!== null`, not `undefined`) | Add `!= null` check |
| N7 | `app.js:483` | MED | `setView("otlog")` reachable via tab click before `graphData` loads; throws on `graphData.ot_commands` | Early-return `if (!graphData) return;` at top of data-dependent view handlers |

### Category 6 — D3 Lifecycle & Frontend State

| ID | File:Line | Severity | Description | Fix |
|----|-----------|----------|-------------|-----|
| L1 | `app.js:619,4198,4242,4271,4282` | HIGH | OT edit state (`otOverrides`, `otRemovedIds`, `otRiskLabels`, `otAddedNodes`) not cleared on new upload — stale overrides from prior PCAP linger invisibly | Clear all four in `loadGraph` |
| L2 | `app.js:931–933` | MED | `renderGraph` stops simulation but does not null-out tick/end handlers; old closures fire briefly after re-render | `simulation.on("tick", null).on("end", null)` before `.stop()` |
| L3 | `app.js:1175` | MED | `setTimeout(() => zoomFit(), 2500)` unconditional; re-uploading within 2.5 s fires stale fit on new graph | Store ID and `clearTimeout` in `loadGraph` |
| L4 | `app.js:4087–4170` | HIGH | `_otLogRendered` gate short-circuits filter button rebuild on subsequent uploads; stale proto/dir sets baked into old listeners | Verify `_otLogRendered = false` at L374 clears old button listeners; if not, detach before re-render |

### Category 7 — Performance

| ID | File:Line | Severity | Description | Fix |
|----|-----------|----------|-------------|-----|
| PF1 | `app.js:4715–4717` | HIGH | `Math.min(...allTimes)` / `Math.max(...allTimes)` with spread — blows call stack ("Maximum call stack size exceeded") on >125k timestamps | Replace with `for`-loop reduce |
| PF2 | `app.js:2658–2667` | HIGH | OT bridge detection is O(N·E): `effectiveNodes.length × data.edges.length` — 1k hosts × 10k edges = 10M iterations per render | Build `edgesByNode` index once before the loop |
| PF3 | `app.js:1958–1962` | MED | `openPktInspectorForHost` concatenates ALL packet arrays and sorts in the main thread — potentially 150k packets, causing multi-second jank | Paginate or warn user when count exceeds threshold |
| PF4 | `app.js:2502–2505` | LOW | `renderConnTable` re-sorts entire edges array on each filter toggle | Sort once on load; filter with pre-sorted array |

### Category 8 — Security

| ID | File:Line | Severity | Description | Fix |
|----|-----------|----------|-------------|-----|
| S1 | `app.py:3037–3038` | HIGH | `--public` binds Werkzeug dev server to `0.0.0.0` with no warning — dev server is not hardened | Print a prominent banner warning before binding; recommend gunicorn in README |
| S2 | `app.py` (global) | MED | No CSRF protection on `/upload` POST; a page on the LAN could trigger uploads against `127.0.0.1:5000` | Add `Origin`/`Referer` check or `Flask-WTF` when `--public` is used |
| S3 | `app.py:309–318` | MED | `_get_geoip_reader` lazy init not protected by a lock; two threads may open the DB concurrently | Wrap init in `threading.Lock()` |
| S4 | `app.py:26–28` | LOW | No `app.secret_key`; harmless now (no sessions), but any future flash/session addition silently uses a random key that changes on restart | Set a static `secret_key` from env var |

### Category 9 — Test Coverage

| ID | Location | Severity | Description | Fix |
|----|----------|----------|-------------|-----|
| T1 | `tests/` | HIGH | No HTTP-layer tests; `/upload` endpoint (happy path, error paths, multi-file, oversize, bad extension) completely untested | Add `tests/test_routes.py` using `app.test_client()` |
| T2 | `tests/test_anomalies.py` | HIGH | 16 of ~25 OT/IoT anomaly rules have no test: `ot_modbus_write`, `ot_modbus_bulk_read`, `ot_modbus_broadcast`, `ot_modbus_exception`, `ot_multiunit_poll`, `ot_dnp3_control`, `ot_dnp3_unusual_fc`, `ot_s7_write`, `ot_s7_critical`, `ot_s7_code_download`, `ot_enip_write`, `ot_iec104_command`, `ot_bacnet_write`, `iot_telnet`, `iot_camera_exfil`, `iot_tr069` | Add `tests/test_anomalies_ot.py` |
| T3 | `tests/test_file_extraction.py:19` | HIGH | Re-implements `_extract_file()` logic locally instead of importing; if app.py changes, tests pass while production breaks | Import the helper from `app.py` |
| T4 | `tests/test_credentials.py` | HIGH | Similarly re-implements form-parse path; same drift risk | Import from `app.py` |
| T5 | `tests/` | MED | No `conftest.py`; packet-builder helpers duplicated across files | Create `tests/conftest.py` with shared fixtures |

### Category 10 — Dependencies & CI

| ID | Location | Severity | Description | Fix |
|----|----------|----------|-------------|-----|
| D1 | `requirements.txt` | HIGH | No pinned versions (`>=` only); CI could install a breaking major upgrade silently | Pin with `==` or use `pip-compile` |
| D2 | `requirements.txt` | MED | No `pytest`, `ruff` in requirements; README tells users to install pytest separately | Add `requirements-dev.txt` |
| D3 | `.github/` | HIGH | No CI workflow; regressions ship without automatic gate | Add `ci.yml` running `pytest -q` + `ruff check` on push |
| D4 | `requirements.txt` | LOW | `cupy` conditionally imported in `app.py` but absent from `requirements.txt` with no comment | Add `# optional: cupy` comment |

### Category 11 — Documentation & Housekeeping

| ID | Location | Severity | Description | Fix |
|----|----------|----------|-------------|-----|
| H1 | `README.md` | LOW | Claims 224 tests; actual count is 216 | Update after Phase D adds new tests |
| H2 | `.gitignore:7` | LOW | `backlog.md` is in `.gitignore` but is committed and present | Remove from `.gitignore` |
| H3 | `README.md` | MED | No warning that `--public` exposes a Werkzeug dev server to the network | Add a security note in the Running section |

---

## Items Deferred to Backlog (MED / LOW)

The following are added to `backlog.md` for incremental cleanup. They do not represent critical risk in the current localhost-only deployment model.

- E3 — `parse_errors` counter surfaced in stats
- E4 — Non-JSON upload error message
- E5 — FileReader onerror
- U4 — Tempfile order-of-operations
- U5 — Suffix whitelist in NamedTemporaryFile
- P3 — BACnet truncation return None
- P4 — IEC104 apdu_len validation
- P5 — MQTT remaining-length comment
- X5–X9 — Lower-priority XSS escaping
- N5–N7 — Minor null-safety gaps
- L2, L3 — D3 simulation tick cleanup, stale zoomFit timeout
- PF3, PF4 — Packet inspector pagination, conn table pre-sort
- S2 — CSRF on /upload when --public
- S3 — GeoIP reader lock
- S4 — Secret key from env
- T5 — conftest.py fixtures
- D4 — cupy comment
- H1–H3 — README / gitignore housekeeping
