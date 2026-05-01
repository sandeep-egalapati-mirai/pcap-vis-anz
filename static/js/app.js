/* ── Colour maps ─────────────────────────────────────────────────────────── */
const HOST_COLORS = {
  "Web Server":      "#4FC3F7",
  "SSH Server":      "#FF7043",
  "FTP Server":      "#FF8A65",
  "DNS Server":      "#81C784",
  "DHCP Server":     "#AED581",
  "Mail Server":     "#CE93D8",
  "Database Server": "#FFB74D",
  "Cache Server":    "#FF8A65",
  "Search Server":   "#F06292",
  "Windows Host":    "#64B5F6",
  "Linux Host":      "#FFA726",
  "Linux Server":    "#FF7043",
  "Network Device":  "#4DB6AC",
  "Router":          "#26A69A",
  "VPN Gateway":     "#7E57C2",
  "Container Host":  "#26C6DA",
  "Directory Server":"#EC407A",
  "Log Server":      "#A1887F",
  "NTP Server":      "#8D6E63",
  "Print Server":    "#90A4AE",
  "Security Tool":   "#EF5350",
  "Remote Desktop":  "#5C6BC0",
  "Telnet Server":   "#FF5722",
  "Internet Host":   "#78909C",
  "Broadcast":       "#37474F",
  "Multicast":       "#455A64",
  "Unknown Host":    "#546E7A",
  "PLC":                    "#FF6B35",
  "RTU":                    "#F7C59F",
  "IED":                    "#EFEFD0",
  "HMI":                    "#FF9F1C",
  "SCADA Server":           "#E71D36",
  "DCS":                    "#C77DFF",
  "Historian":              "#7B2D8B",
  "Engineering Workstation":"#2EC4B6",
  "Building Controller":    "#CBF3F0",
  "IoT Gateway":            "#FFBF69",
  "Field Device":           "#A8DADC",
  "IP Camera":        "#00BCD4",
  "Smart Home Hub":   "#8BC34A",
  "Smart Meter":      "#FFC107",
  "IoT Sensor":       "#03A9F4",
  "Smart Speaker":    "#9C27B0",
  "CPE Device":       "#607D8B",
};

const PROTO_COLORS = {
  "HTTP":       "#42A5F5",
  "HTTPS":      "#26C6DA",
  "DNS":        "#66BB6A",
  "SSH":        "#FFA726",
  "FTP":        "#EC407A",
  "FTP-Data":   "#EC407A",
  "SMTP":       "#AB47BC",
  "SMTPS":      "#AB47BC",
  "IMAP":       "#7E57C2",
  "IMAPS":      "#7E57C2",
  "POP3":       "#9575CD",
  "POP3S":      "#9575CD",
  "SMB":        "#26A69A",
  "RDP":        "#EF5350",
  "ICMP":       "#BDBDBD",
  "TCP":        "#78909C",
  "UDP":        "#90A4AE",
  "ARP":        "#546E7A",
  "NTP":        "#8D6E63",
  "SNMP":       "#5C6BC0",
  "SNMP-Trap":  "#5C6BC0",
  "MySQL":      "#FF7043",
  "PostgreSQL": "#039BE5",
  "MongoDB":    "#43A047",
  "Redis":      "#E53935",
  "mDNS":       "#66BB6A",
  "SSDP":       "#78909C",
  "DHCP":       "#29B6F6",
  "BGP":        "#4DB6AC",
  "Telnet":     "#FF5722",
  "IP":         "#607D8B",
  "Modbus":       "#FF6B35",
  "EtherNet/IP":  "#FF9F1C",
  "S7comm":       "#2196F3",
  "DNP3":         "#9C27B0",
  "IEC-104":      "#E91E63",
  "BACnet":       "#009688",
  "OPC-UA":       "#FF5722",
  "MQTT":         "#795548",
  "MQTT-TLS":     "#8D6E63",
  "PROFINET":     "#3F51B5",
  "HART-IP":      "#607D8B",
  "GE-SRTP":      "#F44336",
  "OMRON-FINS":   "#4CAF50",
  "Emerson-DeltaV":"#FF9800",
  "PROFIBUS":     "#9E9E9E",
  "CoAP":         "#00BCD4",
  "CoAP-DTLS":    "#0097A7",
  "AMQP":         "#FF5722",
  "AMQPS":        "#BF360C",
  "XMPP":         "#4CAF50",
  "XMPP-TLS":     "#388E3C",
  "RTSP":         "#9C27B0",
  "Matter":       "#673AB7",
  "WS-Discovery": "#607D8B",
  "TR-069":       "#F44336",
  "Tuya-IoT":     "#FF9800",
  "Hikvision":    "#795548",
  "Dahua":        "#8D6E63",
  "AMSP":         "#26C6DA",
  "DLMS":         "#F06292",
};

function protoColor(protocols) {
  if (!protocols || !protocols.length) return "#607D8B";
  const priority = [
    "HTTPS","HTTP","SSH","RDP","DNS","SMTP","SMTPS","IMAP","IMAPS",
    "POP3","POP3S","FTP","FTP-Data","MySQL","PostgreSQL","MongoDB",
    "Redis","SMB","SNMP","DHCP","NTP","BGP","ICMP","TCP","UDP",
  ];
  for (const p of priority) {
    if (protocols.includes(p)) return PROTO_COLORS[p] || "#607D8B";
  }
  return PROTO_COLORS[protocols[0]] || "#607D8B";
}

function hostColor(type) {
  return HOST_COLORS[type] || "#546E7A";
}

function fmtBytes(b) {
  if (b < 1024) return b + " B";
  if (b < 1048576) return (b / 1024).toFixed(1) + " KB";
  return (b / 1048576).toFixed(1) + " MB";
}

function fmtNum(n) {
  return n.toLocaleString();
}

function countryFlag(code) {
  if (!code || code.length !== 2) return "";
  const offset = 127397;
  return String.fromCodePoint(...[...code.toUpperCase()].map(c => c.charCodeAt(0) + offset));
}

/* ── State ───────────────────────────────────────────────────────────────── */
let graphData    = null;
let simulation   = null;
let selectedNode = null;
let activeProtos = new Set();
let activeTypes  = new Set();
let searchTerm   = "";
let packetData   = {};
let currentView  = "graph";  // "graph" | "table" | "dns" | "ot"
let currentLayout = "force"; // "force" | "radial" | "cluster"
let anomalyNodeIps = {};     // ip → highest severity
let tableSort = { col: "packet_count", dir: "desc" };

// Timeline state
let tlPlaying = false;
let tlTimer = null;
let tlWindowPct = 100; // full width by default

/* ── DOM refs ────────────────────────────────────────────────────────────── */
const svg            = d3.select("#graph-svg");
const tooltip        = document.getElementById("tooltip");
const detailPanel    = document.getElementById("detail-panel");
const modalOverlay   = document.getElementById("modal-overlay");
const loadingOverlay = document.getElementById("loading-overlay");
const fileInput      = document.getElementById("file-input");
const dropZone       = document.getElementById("drop-zone");
const modalError     = document.getElementById("modal-error");
const truncBanner    = document.getElementById("trunc-banner");
const searchBox      = document.getElementById("search-box");
const graphWrap      = document.getElementById("graph-wrap");
const tableView      = document.getElementById("table-view");
const dnsView        = document.getElementById("dns-view");
const otMapView      = document.getElementById("ot-map-view");
const ctxMenu        = document.getElementById("ctx-menu");

/* ── SVG setup ───────────────────────────────────────────────────────────── */
const zoomGroup  = svg.append("g").attr("id", "zoom-group");
const linksGroup = zoomGroup.append("g").attr("id", "links-layer");
const nodesGroup = zoomGroup.append("g").attr("id", "nodes-layer");

const zoom = d3.zoom()
  .scaleExtent([0.05, 8])
  .on("zoom", (e) => zoomGroup.attr("transform", e.transform));
svg.call(zoom);

/* ── Upload modal ─────────────────────────────────────────────────────────── */
document.getElementById("upload-btn").addEventListener("click", openModal);
dropZone.addEventListener("click", () => fileInput.click());
fileInput.addEventListener("change", () => {
  if (fileInput.files.length > 0) uploadFiles(fileInput.files);
});

dropZone.addEventListener("dragover", (e) => { e.preventDefault(); dropZone.classList.add("drag-over"); });
dropZone.addEventListener("dragleave", () => dropZone.classList.remove("drag-over"));
dropZone.addEventListener("drop", (e) => {
  e.preventDefault();
  dropZone.classList.remove("drag-over");
  if (e.dataTransfer.files.length > 0) uploadFiles(e.dataTransfer.files);
});

modalOverlay.addEventListener("click", (e) => {
  if (e.target === modalOverlay && graphData) closeModal();
});

function openModal() {
  modalError.textContent = "";
  modalOverlay.classList.remove("hidden");
}
function closeModal() {
  modalOverlay.classList.add("hidden");
  fileInput.value = "";
}

async function uploadFiles(files) {
  // Copy to array immediately — closeModal() clears the live FileList via fileInput.value=""
  const fileArray = Array.from(files);
  const allowed = ["pcap","pcapng","cap"];
  for (const file of fileArray) {
    const ext = file.name.split(".").pop().toLowerCase();
    if (!allowed.includes(ext)) {
      modalError.textContent = `Unsupported file type: ${file.name}. Use .pcap, .pcapng, or .cap`;
      return;
    }
  }
  modalError.textContent = "";
  closeModal();
  loadingOverlay.classList.remove("hidden");

  const form = new FormData();
  for (const file of fileArray) form.append("file", file);

  try {
    const resp = await fetch("/upload", { method: "POST", body: form });
    const data = await resp.json();
    if (data.error) {
      alert("Error: " + data.error);
      openModal();
      return;
    }
    loadGraph(data);
  } catch (err) {
    alert("Upload failed: " + err.message);
    openModal();
  } finally {
    loadingOverlay.classList.add("hidden");
  }
}

/* ── Graph rendering ─────────────────────────────────────────────────────── */
function loadGraph(data) {
  graphData = data;
  packetData = data.packets || {};
  closePktInspector();
  selectedNode = null;
  searchTerm = "";
  searchBox.value = "";
  detailPanel.classList.remove("open");

  // Truncation banner
  if (data.stats.truncated) {
    truncBanner.classList.add("visible");
  } else {
    truncBanner.classList.remove("visible");
  }

  // Stats
  document.getElementById("stat-hosts").textContent = fmtNum(data.stats.total_hosts);
  document.getElementById("stat-conns").textContent = fmtNum(data.stats.total_connections);
  document.getElementById("stat-pkts").textContent  = fmtNum(data.stats.total_packets);

  // Build filter sets
  activeProtos = new Set(data.stats.protocols);
  activeTypes  = new Set(data.stats.host_types);

  buildFilters(data);
  buildLegend(data);
  buildAnomalySidebar(data.anomalies || []);
  buildTimeline(data);
  renderGraph(data);
  setView("graph");

  // Load annotations from localStorage
  applyAnnotations();
}

/* ── View switching ──────────────────────────────────────────────────────── */
document.querySelectorAll(".vt-btn").forEach(btn => {
  btn.addEventListener("click", () => setView(btn.dataset.view));
});

function setView(view) {
  currentView = view;
  document.querySelectorAll(".vt-btn").forEach(b => b.classList.toggle("active", b.dataset.view === view));

  const graphEl = document.getElementById("graph-svg");
  const tlBar   = document.getElementById("timeline-bar");
  const pktIns  = document.getElementById("packet-inspector");

  if (view === "graph") {
    graphEl.style.display = "";
    tlBar.classList.remove("hidden");
    tableView.classList.add("hidden");
    dnsView.classList.add("hidden");
    otMapView.classList.add("hidden");
    document.getElementById("graph-controls").style.display = "";
    document.getElementById("legend").style.display = "";
  } else if (view === "table") {
    graphEl.style.display = "none";
    tlBar.classList.add("hidden");
    pktIns.classList.add("hidden");
    graphWrap.classList.remove("pkt-open");
    tableView.classList.remove("hidden");
    dnsView.classList.add("hidden");
    otMapView.classList.add("hidden");
    document.getElementById("graph-controls").style.display = "none";
    document.getElementById("legend").style.display = "none";
    renderConnTable();
  } else if (view === "dns") {
    graphEl.style.display = "none";
    tlBar.classList.add("hidden");
    pktIns.classList.add("hidden");
    graphWrap.classList.remove("pkt-open");
    tableView.classList.add("hidden");
    dnsView.classList.remove("hidden");
    otMapView.classList.add("hidden");
    document.getElementById("graph-controls").style.display = "none";
    document.getElementById("legend").style.display = "none";
    renderDnsMap();
  } else if (view === "ot") {
    graphEl.style.display = "none";
    tlBar.classList.add("hidden");
    pktIns.classList.add("hidden");
    graphWrap.classList.remove("pkt-open");
    tableView.classList.add("hidden");
    dnsView.classList.add("hidden");
    otMapView.classList.remove("hidden");
    document.getElementById("graph-controls").style.display = "none";
    document.getElementById("legend").style.display = "none";
    renderOTMap(graphData);
  }
}

/* ── Filters ─────────────────────────────────────────────────────────────── */
function buildFilters(data) {
  buildFilterList("proto-filters", data.stats.protocols, activeProtos, PROTO_COLORS, "proto");
  buildFilterList("type-filters",  data.stats.host_types, activeTypes,  HOST_COLORS,  "type");
}

function buildFilterList(containerId, items, activeSet, colorMap, kind) {
  const container = document.getElementById(containerId);
  container.innerHTML = "";

  const counts = {};
  if (graphData) {
    if (kind === "proto") {
      graphData.edges.forEach(e => e.protocols.forEach(p => {
        counts[p] = (counts[p] || 0) + 1;
      }));
    } else {
      graphData.nodes.forEach(n => {
        counts[n.host_type] = (counts[n.host_type] || 0) + 1;
      });
    }
  }

  items.forEach(item => {
    const color = colorMap[item] || "#546E7A";
    const div = document.createElement("div");
    div.className = "filter-item";
    const iconSpan = kind === "type" ? `<span class="fi-icon">${hostIcon(item)}</span>` : "";
    div.innerHTML = `
      <input type="checkbox" id="f-${kind}-${CSS.escape(item)}" checked>
      <div class="dot" style="background:${color}"></div>
      ${iconSpan}<label for="f-${kind}-${CSS.escape(item)}">${item}</label>
      <span class="count">${counts[item] || 0}</span>
    `;
    const cb = div.querySelector("input");
    cb.addEventListener("change", () => {
      if (cb.checked) activeSet.add(item);
      else activeSet.delete(item);
      applyFilters();
      if (currentView === "table") renderConnTable();
    });
    container.appendChild(div);
  });
}

function applyFilters() {
  if (!graphData) return;

  const visibleNodeIds = new Set();
  nodesGroup.selectAll(".node").each(function(d) {
    const visible = activeTypes.has(d.host_type) &&
      (!searchTerm || d.ip.includes(searchTerm) ||
       (d.hostname && d.hostname.toLowerCase().includes(searchTerm)));
    d3.select(this).classed("faded", !visible);
    if (visible) visibleNodeIds.add(d.id);
  });

  linksGroup.selectAll(".link").each(function(d) {
    const protoOk = d.protocols.some(p => activeProtos.has(p));
    const sid = d.source.id || d.source;
    const tid = d.target.id || d.target;
    const visible = protoOk && visibleNodeIds.has(sid) && visibleNodeIds.has(tid);
    d3.select(this).classed("faded", !visible);
  });
}

/* ── Anomaly sidebar ─────────────────────────────────────────────────────── */
function buildAnomalySidebar(anomalies) {
  const section = document.getElementById("anomaly-section");
  const list = document.getElementById("anomaly-list");
  list.innerHTML = "";

  if (!anomalies || anomalies.length === 0) {
    section.style.display = "none";
    return;
  }
  section.style.display = "";

  // Build lookup: ip → highest severity
  anomalyNodeIps = {};
  anomalies.forEach(a => {
    const sevOrder = { high: 3, medium: 2, low: 1 };
    const ips = [a.src, a.dst].filter(Boolean);
    ips.forEach(ip => {
      const cur = anomalyNodeIps[ip];
      if (!cur || sevOrder[a.severity] > sevOrder[cur]) {
        anomalyNodeIps[ip] = a.severity;
      }
    });
  });

  anomalies.forEach(a => {
    const div = document.createElement("div");
    div.className = `anomaly-badge ${a.severity}`;
    div.innerHTML = `
      <span class="ab-sev ${a.severity}">${a.severity}</span>
      <span class="ab-desc">${escHtml(a.description)}</span>
    `;
    div.addEventListener("click", () => {
      // Highlight relevant nodes
      if (a.src) {
        const node = graphData && graphData.nodes.find(n => n.ip === a.src);
        if (node) {
          selectedNode = node;
          showDetailPanel(node);
          detailPanel.classList.add("open");
          const linkSel = linksGroup.selectAll(".link");
          const nodeSel = nodesGroup.selectAll(".node");
          nodeSel.classed("selected", n => n.id === node.id);
          highlightNode(node, linkSel, nodeSel);
          setView("graph");
        }
      }
    });
    list.appendChild(div);
  });
}

/* ── D3 force graph ──────────────────────────────────────────────────────── */
function renderGraph(data) {
  linksGroup.selectAll("*").remove();
  nodesGroup.selectAll("*").remove();
  if (simulation) simulation.stop();

  data._nodeMap = {};
  data.nodes.forEach(n => { data._nodeMap[n.id] = n; n._visible = true; });

  const nodes = data.nodes.map(d => ({ ...d }));
  const nodeById = {};
  nodes.forEach(n => nodeById[n.id] = n);

  const links = data.edges
    .filter(e => nodeById[e.source] && nodeById[e.target])
    .map(e => ({ ...e, source: e.source, target: e.target }));

  const maxPkt = Math.max(...nodes.map(n => n.packet_count), 1);
  function nodeRadius(d) {
    return 6 + Math.log1p(d.packet_count / maxPkt * 200) * 3;
  }

  const maxEdgePkt = Math.max(...links.map(e => e.packet_count), 1);
  function edgeWidth(d) {
    return 1 + Math.log1p(d.packet_count / maxEdgePkt * 50) * 1.2;
  }

  // ── Links ──
  // Build Purdue level lookup for cross-zone highlighting
  const _pLevel = {};
  nodes.forEach(n => { _pLevel[n.id] = purdueLevel(n.host_type); });
  const _crossCount = links.filter(e => {
    const sl = _pLevel[typeof e.source === "object" ? e.source.id : e.source] ?? -1;
    const tl = _pLevel[typeof e.target === "object" ? e.target.id : e.target] ?? -1;
    return sl !== -1 && tl !== -1 && sl !== tl;
  }).length;
  // Update sidebar cross-zone badge if present
  const _czBadge = document.getElementById("cross-zone-badge");
  if (_czBadge) _czBadge.textContent = _crossCount > 0 ? `⚠ ${_crossCount} cross-zone` : "";

  const linkSel = linksGroup.selectAll(".link")
    .data(links)
    .join("line")
    .attr("class", d => {
      const sl = _pLevel[typeof d.source === "object" ? d.source.id : d.source] ?? -1;
      const tl = _pLevel[typeof d.target === "object" ? d.target.id : d.target] ?? -1;
      return sl !== -1 && tl !== -1 && sl !== tl ? "link cross-zone" : "link";
    })
    .attr("stroke", d => {
      const sl = _pLevel[typeof d.source === "object" ? d.source.id : d.source] ?? -1;
      const tl = _pLevel[typeof d.target === "object" ? d.target.id : d.target] ?? -1;
      return sl !== -1 && tl !== -1 && sl !== tl ? "#ff8c00" : protoColor(d.protocols);
    })
    .attr("stroke-width", d => edgeWidth(d))
    .on("mouseenter", (event, d) => showTooltipEdge(event, d))
    .on("mousemove", (event) => positionTooltip(event))
    .on("mouseleave", () => hideTooltip())
    .on("click", (event, d) => {
      event.stopPropagation();
      hideTooltip();
      const sid = typeof d.source === "object" ? d.source.id : d.source;
      const tid = typeof d.target === "object" ? d.target.id : d.target;
      openPktInspector(sid, tid);
    });

  // ── Nodes ──
  const nodeSel = nodesGroup.selectAll(".node")
    .data(nodes)
    .join("g")
    .attr("class", "node")
    .call(d3.drag()
      .on("start", (event, d) => {
        if (!event.active) simulation.alphaTarget(0.3).restart();
        d.fx = d.x; d.fy = d.y;
      })
      .on("drag", (event, d) => { d.fx = event.x; d.fy = event.y; })
      .on("end", (event, d) => {
        if (!event.active) simulation.alphaTarget(0);
        d.fx = null; d.fy = null;
      })
    )
    .on("mouseenter", (event, d) => {
      showTooltipNode(event, d);
      highlightNode(d, linkSel, nodeSel);
    })
    .on("mousemove", (event) => positionTooltip(event))
    .on("mouseleave", (event, d) => {
      hideTooltip();
      if (!selectedNode || selectedNode.id !== d.id) {
        unhighlightAll(linkSel, nodeSel);
        if (selectedNode) highlightNode(selectedNode, linkSel, nodeSel);
      }
    })
    .on("click", (event, d) => {
      event.stopPropagation();
      ctxMenu.classList.add("hidden");
      if (selectedNode && selectedNode.id === d.id) {
        selectedNode = null;
        unhighlightAll(linkSel, nodeSel);
        nodeSel.classed("selected", false);
        detailPanel.classList.remove("open");
      } else {
        selectedNode = d;
        nodeSel.classed("selected", n => n.id === d.id);
        highlightNode(d, linkSel, nodeSel);
        showDetailPanel(d);
      }
    })
    .on("contextmenu", (event, d) => {
      event.preventDefault();
      event.stopPropagation();
      showCtxMenu(event, d);
    });

  // Anomaly pulse rings
  nodeSel.each(function(d) {
    const sev = anomalyNodeIps[d.ip];
    if (sev) {
      d3.select(this).append("circle")
        .attr("class", `anomaly-ring-${sev}`)
        .attr("r", nodeRadius(d) + 4);
    }
  });

  // Circle
  nodeSel.append("circle")
    .attr("r", d => nodeRadius(d))
    .attr("fill", d => hostColor(d.host_type))
    .attr("fill-opacity", 0.85)
    .attr("stroke", d => d3.color(hostColor(d.host_type)).brighter(0.5));

  // Icon character
  nodeSel.append("text")
    .attr("class", "node-icon")
    .attr("dy", "0.38em")
    .attr("font-size", d => Math.min(nodeRadius(d) * 1.1, 16) + "px")
    .text(d => hostIcon(d.host_type));

  // IP label below node
  nodeSel.append("text")
    .attr("class", "ip-label")
    .attr("dy", d => nodeRadius(d) + 11)
    .attr("font-size", "9px")
    .attr("fill", "#8b949e")
    .text(d => d.hostname || d.ip);

  // Country code label
  nodeSel.each(function(d) {
    if (d.geo && d.geo.country_code) {
      d3.select(this).append("text")
        .attr("class", "node-geo-label")
        .attr("dy", d => nodeRadius(d) + 21)
        .attr("font-size", "8px")
        .text(d.geo.country_code);
    }
  });

  // Note icon
  nodeSel.each(function(d) {
    const note = getAnnotation(d.ip);
    if (note) {
      d3.select(this).append("text")
        .attr("class", "node-note-icon")
        .attr("dy", d => -(nodeRadius(d) + 4))
        .attr("font-size", "10px")
        .text("✎");
    }
  });

  // Click on background → deselect
  svg.on("click", () => {
    selectedNode = null;
    unhighlightAll(linkSel, nodeSel);
    nodeSel.classed("selected", false);
    detailPanel.classList.remove("open");
    ctxMenu.classList.add("hidden");
  });

  // ── Simulation ──
  const cx = svg.node().clientWidth / 2;
  const cy = svg.node().clientHeight / 2;

  simulation = buildSimulation(nodes, links, cx, cy, currentLayout);
  simulation.on("tick", () => {
    linkSel
      .attr("x1", d => d.source.x)
      .attr("y1", d => d.source.y)
      .attr("x2", d => d.target.x)
      .attr("y2", d => d.target.y);
    nodeSel.attr("transform", d => `translate(${d.x},${d.y})`);
  });

  simulation.on("end", () => zoomFit());
  setTimeout(() => zoomFit(), 2500);
}

function buildSimulation(nodes, links, cx, cy, layout) {
  if (simulation) simulation.stop();

  const _maxPkt = Math.max(...nodes.map(n => n.packet_count), 1);
  const sim = d3.forceSimulation(nodes)
    .force("collide", d3.forceCollide().radius(d => {
      return 6 + Math.log1p(d.packet_count / _maxPkt * 200) * 3 + 12;
    }));

  if (layout === "force") {
    sim
      .force("link", d3.forceLink(links).id(d => d.id).distance(90).strength(0.4))
      .force("charge", d3.forceManyBody().strength(-200).distanceMax(400))
      .force("center", d3.forceCenter(cx, cy));
  } else if (layout === "radial") {
    sim
      .force("link", d3.forceLink(links).id(d => d.id).distance(60).strength(0.3))
      .force("charge", d3.forceManyBody().strength(-100))
      .force("radial", d3.forceRadial(d => d.is_private ? 150 : 350, cx, cy).strength(0.8));
  } else if (layout === "cluster") {
    const typeGroups = {};
    let gIdx = 0;
    nodes.forEach(n => {
      if (!(n.host_type in typeGroups)) typeGroups[n.host_type] = gIdx++;
    });
    const total = gIdx || 1;
    sim
      .force("link", d3.forceLink(links).id(d => d.id).distance(50).strength(0.2))
      .force("charge", d3.forceManyBody().strength(-80))
      .force("x", d3.forceX(d => {
        const gi = typeGroups[d.host_type] || 0;
        return cx + Math.cos((gi / total) * 2 * Math.PI) * 280;
      }).strength(0.5))
      .force("y", d3.forceY(d => {
        const gi = typeGroups[d.host_type] || 0;
        return cy + Math.sin((gi / total) * 2 * Math.PI) * 220;
      }).strength(0.5));
  }

  return sim;
}

/* ── Layout mode buttons ─────────────────────────────────────────────────── */
document.querySelectorAll(".layout-btn").forEach(btn => {
  btn.addEventListener("click", () => {
    if (!graphData) return;
    currentLayout = btn.dataset.layout;
    document.querySelectorAll(".layout-btn").forEach(b => b.classList.toggle("active", b.dataset.layout === currentLayout));
    // Reheat with new forces
    const linkSel = linksGroup.selectAll(".link");
    const nodeSel = nodesGroup.selectAll(".node");
    const nodes = [];
    nodeSel.each(d => nodes.push(d));
    const links = [];
    linkSel.each(d => links.push(d));
    const cx = svg.node().clientWidth / 2;
    const cy = svg.node().clientHeight / 2;
    simulation = buildSimulation(nodes, links, cx, cy, currentLayout);
    simulation.on("tick", () => {
      linkSel
        .attr("x1", d => d.source.x).attr("y1", d => d.source.y)
        .attr("x2", d => d.target.x).attr("y2", d => d.target.y);
      nodeSel.attr("transform", d => `translate(${d.x},${d.y})`);
    });
    simulation.alpha(0.8).restart();
  });
});

/* ── Highlight helpers ───────────────────────────────────────────────────── */
function highlightNode(d, linkSel, nodeSel) {
  const connectedIds = new Set([d.id]);
  linkSel.each(function(e) {
    const sid = e.source.id || e.source;
    const tid = e.target.id || e.target;
    if (sid === d.id || tid === d.id) {
      connectedIds.add(sid);
      connectedIds.add(tid);
    }
  });

  linkSel.classed("highlighted", e => {
    const sid = e.source.id || e.source;
    const tid = e.target.id || e.target;
    return sid === d.id || tid === d.id;
  }).classed("faded", e => {
    const sid = e.source.id || e.source;
    const tid = e.target.id || e.target;
    return sid !== d.id && tid !== d.id;
  });

  nodeSel.classed("faded", n => !connectedIds.has(n.id));
}

function unhighlightAll(linkSel, nodeSel) {
  linkSel.classed("highlighted", false).classed("faded", false);
  nodeSel.classed("faded", false);
  applyFilters();
}

/* ── Tooltip helpers ─────────────────────────────────────────────────────── */
function showTooltipNode(event, d) {
  const geoStr = d.geo ? ` · ${d.geo.country_code || d.geo.country || ""}${d.geo.city ? ", " + d.geo.city : ""}` : "";
  tooltip.innerHTML = `
    <div class="tip-ip">${d.ip}${geoStr ? `<span style="color:var(--text2)">${geoStr}</span>` : ""}</div>
    ${d.hostname ? `<div class="tip-type">${escHtml(d.hostname)}</div>` : ""}
    <div class="tip-type">${d.host_type}${d.os_hint ? " · " + d.os_hint : ""}</div>
    <div class="tip-proto">
      ${d.protocols.slice(0, 6).map(p =>
        `<span style="color:${PROTO_COLORS[p] || '#aaa'}">${p}</span>`
      ).join(" · ")}
    </div>
    <div class="tip-type" style="margin-top:4px">
      ${fmtNum(d.packet_count)} pkts · ${fmtBytes(d.bytes_sent + d.bytes_recv)}
    </div>
    ${anomalyNodeIps[d.ip] ? `<div style="margin-top:4px;font-size:10px;color:${anomalyNodeIps[d.ip]==='high'?'var(--red)':'var(--yellow)'}">⚠ ${anomalyNodeIps[d.ip].toUpperCase()} anomaly</div>` : ""}
  `;
  tooltip.classList.add("visible");
  positionTooltip(event);
}

function showTooltipEdge(event, d) {
  tooltip.innerHTML = `
    <div class="tip-ip" style="font-size:11px">${d.source.id || d.source} ↔ ${d.target.id || d.target}</div>
    <div class="tip-type">${fmtNum(d.packet_count)} pkts · ${fmtBytes(d.bytes)}</div>
    <div class="tip-proto" style="margin-top:4px">
      ${d.protocols.slice(0, 6).map(p =>
        `<span style="color:${PROTO_COLORS[p] || '#aaa'}">${p}</span>`
      ).join(" · ")}
    </div>
    ${d.ports.length ? `<div class="tip-type" style="margin-top:4px">Ports: ${d.ports.slice(0,8).join(", ")}</div>` : ""}
  `;
  tooltip.classList.add("visible");
  positionTooltip(event);
}

function positionTooltip(event) {
  const x = event.clientX + 14;
  const y = event.clientY - 10;
  tooltip.style.left = x + "px";
  tooltip.style.top  = y + "px";
}

function hideTooltip() {
  tooltip.classList.remove("visible");
}

/* ── Detail panel ─────────────────────────────────────────────────────────── */
function showDetailPanel(d) {
  detailPanel.classList.add("open");
  document.getElementById("dh-ip").textContent = d.ip;
  document.getElementById("dh-hostname").textContent =
    d.hostname || d.dns_names[0] || "";

  const body = document.getElementById("detail-body");
  const rows = [];

  rows.push(row("Type", badge(d.host_type, hostColor(d.host_type))));
  const OT_TYPES = new Set(["PLC","RTU","IED","HMI","SCADA Server","DCS","Historian","Engineering Workstation","Building Controller","IoT Gateway","Field Device"]);
  const IOT_TYPES = new Set(["IP Camera","Smart Home Hub","Smart Meter","IoT Sensor","Smart Speaker","CPE Device","IoT Gateway"]);
  if (OT_TYPES.has(d.host_type)) {
    rows.push(`<div class="ot-device-badge">&#9881; OT/ICS Device</div>`);
  }
  // Purdue level badge
  {
    const lvl = (d.purdue_level !== undefined) ? d.purdue_level : purdueLevel(d);
    const levelRow = PURDUE_LEVELS.find(r => r.level === lvl);
    const levelLabel = levelRow ? levelRow.label : "? Unclassified";
    const levelColor = LEVEL_COLORS[lvl] ? LEVEL_COLORS[lvl] : "#444";
    rows.push(`<div style="margin-top:4px"><span style="background:${levelColor}55;border:1px solid ${levelColor}99;color:#ccc;padding:2px 8px;border-radius:10px;font-size:10px;font-family:var(--font-mono)">Purdue ${levelLabel}</span></div>`);
  }
  if (IOT_TYPES.has(d.host_type)) {
    rows.push(`<div class="iot-device-badge">&#128267; IoT Device</div>`);
  }
  if (d.os_hint)     rows.push(row("OS guess",   mono(d.os_hint)));
  if (d.mac)         rows.push(row("MAC", mono(d.mac) + (d.mac_vendor ? ` <span style="color:var(--text2)">(${d.mac_vendor})</span>` : "")));
  rows.push(row("Traffic",
    `<span style="color:#3fb950">↑ ${fmtBytes(d.bytes_sent)}</span>  ` +
    `<span style="color:#58a6ff">↓ ${fmtBytes(d.bytes_recv)}</span>`));
  rows.push(row("Packets", mono(fmtNum(d.packet_count))));
  rows.push(row("Private IP", mono(d.is_private ? "Yes" : "No")));

  // Geo info
  if (d.geo) {
    const flagStr = d.geo.country_code ? countryFlag(d.geo.country_code) + " " : "";
    const geoStr = [
      d.geo.country || "",
      d.geo.city || "",
    ].filter(Boolean).join(", ");
    rows.push(row("Location", `${flagStr}${geoStr || "Unknown"}`));
  }

  if (d.protocols.length) {
    rows.push(sectionTitle("Protocols"));
    rows.push(tagList(d.protocols, p => PROTO_COLORS[p] || "#607D8B", true));
  }

  if (d.services.length) {
    rows.push(sectionTitle("Services detected"));
    rows.push(tagList(d.services, () => null, false));
  }

  if (d.open_ports.length) {
    rows.push(sectionTitle("Ports seen"));
    rows.push(`<div class="d-val" style="font-family:var(--font-mono);font-size:11px;padding-left:0;margin-bottom:6px">${
      d.open_ports.slice(0, 20).join(", ")
    }</div>`);
  }

  if (d.dns_names.length) {
    rows.push(sectionTitle("DNS names"));
    d.dns_names.forEach(n => rows.push(`<div class="d-val" style="font-family:var(--font-mono);font-size:11px;margin-bottom:3px">${escHtml(n)}</div>`));
  }

  if (d.dns_queries.length) {
    rows.push(sectionTitle("DNS queries sent"));
    d.dns_queries.forEach(q => rows.push(`<div class="d-val" style="font-family:var(--font-mono);font-size:11px;margin-bottom:3px;color:var(--text2)">${escHtml(q)}</div>`));
  }

  // Anomalies for this node
  const nodeAnomalies = (graphData.anomalies || []).filter(a => a.src === d.ip || a.dst === d.ip);
  if (nodeAnomalies.length) {
    rows.push(sectionTitle("Anomalies"));
    nodeAnomalies.forEach(a => {
      rows.push(`<div class="anomaly-badge ${a.severity}" style="margin-bottom:4px">
        <span class="ab-sev ${a.severity}">${a.severity}</span>
        <span class="ab-desc">${escHtml(a.description)}</span>
      </div>`);
    });
  }

  // OT Analysis section (for OT host types)
  const CORE_OT_TYPES = new Set(["PLC","RTU","IED","HMI","SCADA Server","DCS","Historian","Engineering Workstation","Building Controller","Field Device"]);
  if (CORE_OT_TYPES.has(d.host_type) && graphData) {
    rows.push(sectionTitle("OT Analysis"));
    const roleColor = { master: "#3fb950", outstation: "#58a6ff", unknown: "#8b949e" }[d.ot_role || "unknown"] || "#8b949e";
    rows.push(`<div style="margin-bottom:6px"><span style="background:${roleColor};color:#000;padding:2px 8px;border-radius:10px;font-size:11px;font-weight:600">${(d.ot_role || "unknown").toUpperCase()}</span></div>`);

    // Read/Write ratio bar
    const connEdges = graphData.edges.filter(e => e.source === d.ip || e.target === d.ip);
    const totR = connEdges.reduce((s, e) => s + (e.ot_reads || 0), 0);
    const totW = connEdges.reduce((s, e) => s + (e.ot_writes || 0), 0);
    const totE = connEdges.reduce((s, e) => s + (e.ot_errors || 0), 0);
    if (totR + totW + totE > 0) {
      const tot = totR + totW + totE;
      const rPct = Math.round(totR / tot * 100);
      const wPct = Math.round(totW / tot * 100);
      const ePct = 100 - rPct - wPct;
      rows.push(`<div style="font-size:11px;color:var(--text2);margin-bottom:3px">Reads: ${totR} · Writes: ${totW} · Errors: ${totE}</div>`);
      rows.push(`<div style="display:flex;height:10px;border-radius:4px;overflow:hidden;margin-bottom:8px">
        <div style="width:${rPct}%;background:#3fb950" title="Reads ${rPct}%"></div>
        <div style="width:${wPct}%;background:#f85149" title="Writes ${wPct}%"></div>
        <div style="width:${ePct}%;background:#d29922" title="Errors ${ePct}%"></div>
      </div>`);
    }
    if (d.modbus_unit_ids && d.modbus_unit_ids.length) {
      rows.push(`<div style="font-size:11px;color:var(--text2)">Modbus unit IDs: <span style="font-family:var(--font-mono)">${d.modbus_unit_ids.join(", ")}</span></div>`);
    }
    if (d.dnp3_addresses && d.dnp3_addresses.length) {
      rows.push(`<div style="font-size:11px;color:var(--text2);margin-top:3px">DNP3 link addresses: <span style="font-family:var(--font-mono)">${d.dnp3_addresses.join(", ")}</span></div>`);
    }
  }

  // Conversations (top 5 edges)
  if (graphData) {
    const convEdges = graphData.edges.filter(e => e.source === d.ip || e.target === d.ip)
      .sort((a, b) => b.packet_count - a.packet_count)
      .slice(0, 5);
    if (convEdges.length) {
      rows.push(sectionTitle("Top Conversations"));
      let tableHtml = `<table class="conv-table">
        <thead><tr><th>Peer</th><th>Proto</th><th>Pkts</th><th>Bytes</th></tr></thead>
        <tbody>`;
      convEdges.forEach(e => {
        const peer = e.source === d.ip ? e.target : e.source;
        const proto = e.protocols.slice(0, 2).join("/");
        tableHtml += `<tr data-sid="${e.source}" data-tid="${e.target}">
          <td title="${peer}">${peer}</td>
          <td>${proto}</td>
          <td>${fmtNum(e.packet_count)}</td>
          <td>${fmtBytes(e.bytes)}</td>
        </tr>`;
      });
      tableHtml += "</tbody></table>";
      rows.push(tableHtml);
    }
  }

  // Annotation
  const note = getAnnotation(d.ip);
  rows.push(sectionTitle("Note"));
  if (note) {
    rows.push(`<div class="annotation-box">${escHtml(note)}</div>`);
    rows.push(`<button class="annotation-edit-btn" id="ann-edit-btn">Edit note</button>`);
  } else {
    rows.push(`<button class="annotation-edit-btn" id="ann-edit-btn">+ Add note</button>`);
  }

  body.innerHTML = rows.join("");

  // Bind conversation table click
  body.querySelectorAll(".conv-table tbody tr").forEach(tr => {
    tr.addEventListener("click", () => {
      openPktInspector(tr.dataset.sid, tr.dataset.tid);
    });
  });

  // Bind annotation button
  const annBtn = body.querySelector("#ann-edit-btn");
  if (annBtn) {
    annBtn.addEventListener("click", () => {
      const existing = getAnnotation(d.ip);
      const input = prompt("Add a note for " + d.ip + ":", existing || "");
      if (input !== null) {
        saveAnnotation(d.ip, input);
        showDetailPanel(d);  // re-render
        // update node icon
        updateNoteIcon(d.ip, !!input);
      }
    });
  }

  // "View Packets" button
  const vpBtn = document.createElement("button");
  vpBtn.className = "btn-view-pkts";
  vpBtn.textContent = "View Packets for this host";
  vpBtn.addEventListener("click", () => openPktInspectorForHost(d.ip));
  body.appendChild(vpBtn);
}

function row(key, val) {
  return `<div class="d-row"><span class="d-key">${key}</span><span class="d-val">${val}</span></div>`;
}
function mono(val) { return `<code style="font-family:var(--font-mono)">${val}</code>`; }
function sectionTitle(t) { return `<div class="d-section-title">${t}</div>`; }
function badge(text, color) {
  return `<span class="tag" style="background:${color}22;border-color:${color};color:${color}">${text}</span>`;
}
function tagList(items, colorFn, isProto) {
  return `<div class="tag-list">${items.map(i => {
    const c = colorFn(i);
    const style = c ? `style="background:${c}22;border-color:${c};color:${c}"` : "";
    return `<span class="tag${isProto ? " proto" : ""}" ${style}>${i}</span>`;
  }).join("")}</div>`;
}

document.getElementById("detail-close").addEventListener("click", () => {
  detailPanel.classList.remove("open");
  selectedNode = null;
  if (graphData) {
    const linkSel  = linksGroup.selectAll(".link");
    const nodeSel  = nodesGroup.selectAll(".node");
    unhighlightAll(linkSel, nodeSel);
    nodeSel.classed("selected", false);
  }
  // Re-render OT map to reclaim space if it was active
  if (currentView === "ot" && graphData) setTimeout(() => renderOTMap(graphData), 50);
});

/* ── Search ──────────────────────────────────────────────────────────────── */
let _searchTimer;
searchBox.addEventListener("input", () => {
  clearTimeout(_searchTimer);
  _searchTimer = setTimeout(() => {
    searchTerm = searchBox.value.trim().toLowerCase();
    applyFilters();

    if (searchTerm && graphData) {
      const match = graphData.nodes.find(n =>
        n.ip.includes(searchTerm) ||
        (n.hostname && n.hostname.toLowerCase().includes(searchTerm))
      );
      if (match) {
        selectedNode = match;
        showDetailPanel(match);
        detailPanel.classList.add("open");
      }
    }
  }, 300);
});

/* ── Zoom controls ────────────────────────────────────────────────────────── */
document.getElementById("btn-zoom-in").addEventListener("click", () =>
  svg.transition().call(zoom.scaleBy, 1.4)
);
document.getElementById("btn-zoom-out").addEventListener("click", () =>
  svg.transition().call(zoom.scaleBy, 0.7)
);
document.getElementById("btn-zoom-fit").addEventListener("click", zoomFit);

function zoomFit() {
  const bounds = zoomGroup.node().getBBox();
  if (!bounds.width || !bounds.height) return;
  const svgEl = svg.node();
  const w = svgEl.clientWidth;
  const h = svgEl.clientHeight;
  const padding = 40;
  const scale = Math.min(
    (w - padding * 2) / bounds.width,
    (h - padding * 2) / bounds.height,
    2
  );
  const tx = w / 2 - scale * (bounds.x + bounds.width / 2);
  const ty = h / 2 - scale * (bounds.y + bounds.height / 2);
  svg.transition().duration(600)
    .call(zoom.transform, d3.zoomIdentity.translate(tx, ty).scale(scale));
}

/* ── Legend ──────────────────────────────────────────────────────────────── */
function buildLegend(data) {
  const hostLegend = document.getElementById("legend-hosts");
  hostLegend.innerHTML = "";
  data.stats.host_types.forEach(ht => {
    const div = document.createElement("div");
    div.className = "legend-row";
    div.innerHTML = `<span class="legend-icon">${hostIcon(ht)}</span><div class="legend-dot" style="background:${hostColor(ht)}"></div><span>${ht}</span>`;
    hostLegend.appendChild(div);
  });
}

/* ── Host icon ───────────────────────────────────────────────────────────── */
function hostIcon(type) {
  const icons = {
    // IT servers
    "Web Server":      "🌐",
    "DNS Server":      "🔍",
    "DHCP Server":     "🗄️",
    "SSH Server":      "🔒",
    "Telnet Server":   "💻",
    "FTP Server":      "📁",
    "Mail Server":     "✉️",
    "Database Server": "🗄️",
    "Cache Server":    "⚡",
    // IT hosts
    "Windows Host":    "🖥️",
    "Linux Host":      "🐧",
    "Linux Server":    "🐧",
    "Network Device":  "🔀",
    "Router":          "📡",
    "VPN Gateway":     "🛡️",
    "Container Host":  "📦",
    "Internet Host":   "🌍",
    "Broadcast":       "📢",
    "Multicast":       "📢",
    // OT / ICS
    "PLC":                    "⚙️",
    "RTU":                    "📟",
    "IED":                    "⚡",
    "HMI":                    "🖥️",
    "SCADA Server":           "🏭",
    "DCS":                    "🏭",
    "Historian":               "📊",
    "Engineering Workstation": "🔧",
    "Building Controller":     "🏢",
    "IoT Gateway":             "🔗",
    "Field Device":            "🔌",
    // IoT
    "IP Camera":       "📷",
    "Smart Home Hub":  "🏠",
    "Smart Meter":     "📊",
    "IoT Sensor":      "📡",
    "Smart Speaker":   "🔊",
    "CPE Device":      "📡",
  };
  return icons[type] || "❓";
}

/* ── On page load: show upload modal ─────────────────────────────────────── */
window.addEventListener("load", () => {
  loadingOverlay.classList.add("hidden");
  modalOverlay.classList.remove("hidden");
});

/* ── Packet Inspector ─────────────────────────────────────────────────────── */
const pktInspector  = document.getElementById("packet-inspector");
const pktConnLabel  = document.getElementById("pkt-conn-label");
const pktTbody      = document.getElementById("pkt-tbody");
const pktTree       = document.getElementById("pkt-tree");
const pktHex        = document.getElementById("pkt-hex");
const pktTreeEmpty  = document.getElementById("pkt-tree-empty");
const pktHexEmpty   = document.getElementById("pkt-hex-empty");

document.getElementById("pkt-close").addEventListener("click", closePktInspector);
document.getElementById("pkt-tab-pkts").addEventListener("click", () => {
  const key = pktConnLabel.textContent.split("  ↔  ").map(s => s.trim())[0];
  _switchPktTab("pkts", []);
  document.getElementById("pkt-list-wrap").classList.remove("hidden");
  document.getElementById("pkt-cmd-log").classList.add("hidden");
  document.getElementById("pkt-tab-pkts").classList.add("active");
  document.getElementById("pkt-tab-cmds").classList.remove("active");
});
document.getElementById("pkt-tab-cmds").addEventListener("click", () => {
  // gather current packets from the visible table rows' data
  const allKeys = Object.keys(packetData);
  let curPkts = [];
  for (const k of allKeys) { if (packetData[k].length) { curPkts = packetData[k]; break; } }
  // best effort: find packets by reading what's shown
  const label = pktConnLabel.textContent;
  const m = label.match(/^(.+?)  ↔  (.+?)  ·/);
  if (m) {
    const key = [m[1].trim(), m[2].trim()].sort().join("|");
    curPkts = packetData[key] || [];
  }
  _switchPktTab("cmds", curPkts);
});

const OT_PKT_FIELDS = ["modbus","dnp3","s7comm","enip","iec104","bacnet"];

function _switchPktTab(tab, pkts) {
  const listWrap = document.getElementById("pkt-list-wrap");
  const cmdLog   = document.getElementById("pkt-cmd-log");
  const tabPkts  = document.getElementById("pkt-tab-pkts");
  const tabCmds  = document.getElementById("pkt-tab-cmds");
  if (tab === "cmds") {
    listWrap.classList.add("hidden");
    cmdLog.classList.remove("hidden");
    tabPkts.classList.remove("active");
    tabCmds.classList.add("active");
    renderCmdLog(pkts);
  } else {
    cmdLog.classList.add("hidden");
    listWrap.classList.remove("hidden");
    tabPkts.classList.add("active");
    tabCmds.classList.remove("active");
  }
}

function renderCmdLog(pkts) {
  const cmdLog = document.getElementById("pkt-cmd-log");
  const otPkts = pkts.filter(p => OT_PKT_FIELDS.some(f => p[f]));
  if (!otPkts.length) {
    cmdLog.innerHTML = `<div style="padding:12px;color:var(--text2);font-size:12px">No OT/ICS protocol commands in this capture.</div>`;
    return;
  }
  const t0 = pkts[0]?.time || 0;
  let html = `<table class="pkt-cmd-table"><thead><tr>
    <th>Time</th><th>Protocol</th><th>Direction</th><th>Function</th><th>Detail</th><th>Result</th>
  </tr></thead><tbody>`;
  otPkts.forEach(p => {
    let proto = "", dir = "", fn = "", detail = "", result = "";
    const isW_cls = p.modbus?.is_write || p.dnp3?.is_write || p.s7comm?.is_write || p.enip?.is_write || p.iec104?.is_write || p.bacnet?.is_write;
    if (p.modbus) {
      proto = "Modbus";
      dir = p.src < p.dst ? "→" : "←";
      fn = `FC${p.modbus.function_code} ${p.modbus.function_name}`;
      if (p.modbus.register_address != null) detail = `@${p.modbus.register_address}`;
      if (p.modbus.quantity != null) detail += ` ×${p.modbus.quantity}`;
      result = p.modbus.exception_code ? `ERR: ${escHtml(p.modbus.exception_name || p.modbus.exception_code)}` : "OK";
    } else if (p.dnp3) {
      proto = "DNP3";
      dir = p.dnp3.role === "master" ? "→" : "←";
      fn = `FC${p.dnp3.function_code} ${p.dnp3.function_name}`;
      if (p.dnp3.data_object_group) detail = p.dnp3.data_object_group;
      result = p.dnp3.is_error ? "ERR" : "OK";
    } else if (p.s7comm) {
      proto = "S7comm";
      dir = p.s7comm.rosctr === 1 ? "→" : "←";
      fn = `${p.s7comm.function_name}`;
      if (p.s7comm.block_type) { detail = p.s7comm.block_type; if (p.s7comm.block_number != null) detail += ` #${p.s7comm.block_number}`; }
      result = p.s7comm.is_error ? "ERR" : "OK";
    } else if (p.enip) {
      proto = "EtherNet/IP";
      dir = p.enip.is_response ? "←" : "→";
      fn = p.enip.cip_service_name || p.enip.command_name;
      result = p.enip.is_error ? "ERR" : "OK";
    } else if (p.iec104) {
      proto = "IEC-104";
      dir = "→";
      fn = p.iec104.type_name || p.iec104.frame_type;
      detail = p.iec104.cot_name || "";
      result = p.iec104.is_error ? "ERR" : "OK";
    } else if (p.bacnet) {
      proto = "BACnet";
      dir = "→";
      fn = p.bacnet.service_name || p.bacnet.pdu_type_name;
      result = p.bacnet.is_error ? "ERR" : "OK";
    }
    const rowCls = result.startsWith("ERR") ? "cmd-err" : (isW_cls ? "cmd-write" : "cmd-read");
    html += `<tr class="${rowCls}">
      <td>${(p.time - t0).toFixed(3)}s</td>
      <td>${proto}</td>
      <td style="font-weight:700">${dir}</td>
      <td style="font-family:var(--font-mono);font-size:11px">${escHtml(fn)}</td>
      <td style="font-family:var(--font-mono);font-size:11px;color:var(--text2)">${escHtml(detail)}</td>
      <td class="${result.startsWith("ERR") ? "cmd-result-err" : "cmd-result-ok"}">${escHtml(result)}</td>
    </tr>`;
  });
  html += "</tbody></table>";
  cmdLog.innerHTML = html;
}

function openPktInspector(sid, tid) {
  const key = [sid, tid].sort().join("|");
  const pkts = packetData[key] || [];
  pktConnLabel.textContent = `${sid}  ↔  ${tid}  ·  ${pkts.length} packet${pkts.length !== 1 ? "s" : ""} captured`;
  _switchPktTab("pkts", pkts);
  renderPktTable(pkts);
  // Show Cmd Log tab only if there are OT packets
  const hasOT = pkts.some(p => OT_PKT_FIELDS.some(f => p[f]));
  document.getElementById("pkt-tab-cmds").style.display = hasOT ? "" : "none";
  pktInspector.classList.remove("hidden");
  graphWrap.classList.add("pkt-open");
}

function openPktInspectorForHost(ip) {
  const allPkts = [];
  for (const [key, pkts] of Object.entries(packetData)) {
    const [a, b] = key.split("|");
    if (a === ip || b === ip) allPkts.push(...pkts);
  }
  allPkts.sort((a, b) => a.time - b.time);
  pktConnLabel.textContent = `Host ${ip}  ·  ${allPkts.length} packet${allPkts.length !== 1 ? "s" : ""} captured`;
  _switchPktTab("pkts", allPkts);
  renderPktTable(allPkts);
  const hasOT = allPkts.some(p => OT_PKT_FIELDS.some(f => p[f]));
  document.getElementById("pkt-tab-cmds").style.display = hasOT ? "" : "none";
  pktInspector.classList.remove("hidden");
  graphWrap.classList.add("pkt-open");
}

function closePktInspector() {
  pktInspector.classList.add("hidden");
  graphWrap.classList.remove("pkt-open");
  document.getElementById("legend").style.bottom = "";
  document.getElementById("graph-controls").style.bottom = "";
  pktTbody.innerHTML = "";
  pktTree.innerHTML = "";
  pktHex.innerHTML = "";
  pktTreeEmpty.style.display = "block";
  pktHexEmpty.style.display = "block";
}

const PKT_PAGE_SIZE = 20;

function _appendPktRows(pkts, t0, start, end) {
  for (let i = start; i < end && i < pkts.length; i++) {
    const p = pkts[i];
    const tr = document.createElement("tr");
    tr.className = protoRowClass(p.protocol);
    const srcStr = p.src + (p.sport != null ? ":" + p.sport : "");
    const dstStr = p.dst + (p.dport != null ? ":" + p.dport : "");
    tr.innerHTML = `
      <td>${i + 1}</td>
      <td>${(p.time - t0).toFixed(6)}</td>
      <td title="${srcStr}">${srcStr}</td>
      <td title="${dstStr}">${dstStr}</td>
      <td>${p.protocol}</td>
      <td>${p.len}</td>
      <td title="${escHtml(p.info || "")}">${escHtml(p.info || "")}</td>
    `;
    tr.addEventListener("click", () => {
      pktTbody.querySelectorAll("tr.selected").forEach(r => r.classList.remove("selected"));
      tr.classList.add("selected");
      renderPktDetail(p);
    });
    pktTbody.appendChild(tr);
  }
}

function renderPktTable(pkts) {
  pktTbody.innerHTML = "";
  pktTree.innerHTML = "";
  pktHex.innerHTML = "";
  pktTreeEmpty.style.display = "block";
  pktHexEmpty.style.display = "block";

  const t0 = pkts.length ? pkts[0].time : 0;
  _appendPktRows(pkts, t0, 0, PKT_PAGE_SIZE);

  if (pkts.length > PKT_PAGE_SIZE) {
    const moreRow = document.createElement("tr");
    moreRow.innerHTML = `<td colspan="7" style="text-align:center;cursor:pointer;color:var(--accent)">Load ${pkts.length - PKT_PAGE_SIZE} more packets…</td>`;
    moreRow.addEventListener("click", () => {
      moreRow.remove();
      _appendPktRows(pkts, t0, PKT_PAGE_SIZE, pkts.length);
    });
    pktTbody.appendChild(moreRow);
  }
}

function protoRowClass(proto) {
  const p = (proto || "").toUpperCase();
  if (p === "HTTP")  return "pr-http";
  if (p === "HTTPS") return "pr-https";
  if (p === "DNS")   return "pr-dns";
  if (p === "SSH")   return "pr-ssh";
  if (p === "ICMP")  return "pr-icmp";
  if (p === "UDP")   return "pr-udp";
  return "pr-tcp";
}

function renderPktDetail(p) {
  pktTree.innerHTML = "";
  pktTreeEmpty.style.display = "none";
  (p.layers || []).forEach(layer => {
    const div = document.createElement("div");
    div.className = "pkt-layer";
    const hdr = document.createElement("div");
    hdr.className = "pkt-layer-header";
    hdr.innerHTML = `<span class="pkt-arrow">&#9660;</span> ${layer.name}`;
    hdr.addEventListener("click", () => div.classList.toggle("collapsed"));
    const fields = document.createElement("div");
    fields.className = "pkt-layer-fields";
    (layer.fields || []).forEach(f => {
      const frow = document.createElement("div");
      frow.className = "pkt-field";
      frow.innerHTML = `<span class="pkt-fk">${escHtml(String(f.k))}:</span><span class="pkt-fv">${escHtml(String(f.v))}</span>`;
      fields.appendChild(frow);
    });
    div.appendChild(hdr);
    div.appendChild(fields);
    pktTree.appendChild(div);
  });

  // HTTP section
  if (p.http) {
    const httpDiv = document.createElement("div");
    httpDiv.className = "pkt-layer";
    const hdr = document.createElement("div");
    hdr.className = "pkt-layer-header";
    hdr.innerHTML = `<span class="pkt-arrow">&#9660;</span> Hypertext Transfer Protocol`;
    hdr.addEventListener("click", () => httpDiv.classList.toggle("collapsed"));
    const content = document.createElement("div");
    content.className = "pkt-http-section";

    if (p.http.type === "request") {
      content.innerHTML = `
        <div class="pkt-http-request-line">${escHtml(p.http.method)} ${escHtml(p.http.url)} ${escHtml(p.http.version || "")}</div>
        ${buildHttpHeadersTable(p.http.headers)}
        ${p.http.body_preview ? `<div style="font-size:10px;color:var(--text2);margin-bottom:3px">Body preview:</div><pre class="pkt-http-body-preview">${escHtml(p.http.body_preview)}</pre>` : ""}
      `;
    } else if (p.http.type === "response") {
      const statusClass = p.http.status_code >= 400 ? "pkt-http-status-err" : "pkt-http-status-ok";
      content.innerHTML = `
        <div class="pkt-http-status-line ${statusClass}">${escHtml(p.http.version || "")} ${p.http.status_code} ${escHtml(p.http.reason || "")}</div>
        ${buildHttpHeadersTable(p.http.headers)}
        ${p.http.body_preview ? `<div style="font-size:10px;color:var(--text2);margin-bottom:3px">Body preview:</div><pre class="pkt-http-body-preview">${escHtml(p.http.body_preview)}</pre>` : ""}
      `;
    }

    httpDiv.appendChild(hdr);
    httpDiv.appendChild(content);
    pktTree.appendChild(httpDiv);
  }

  // Modbus section
  if (p.modbus) {
    const mb = p.modbus;
    const mbDiv = document.createElement("div");
    mbDiv.className = "pkt-layer";
    const hdr = document.createElement("div");
    hdr.className = "pkt-layer-header";
    const fcColor = mb.is_write ? "var(--red)" : mb.is_error ? "var(--yellow)" : "var(--green)";
    hdr.innerHTML = `<span class="pkt-arrow">&#9660;</span> <span style="color:${fcColor}">Modbus TCP</span>`;
    hdr.addEventListener("click", () => mbDiv.classList.toggle("collapsed"));
    const fields = document.createElement("div");
    fields.className = "pkt-layer-fields";
    const mbFields = [
      {k: "Transaction ID", v: mb.transaction_id},
      {k: "Unit ID",        v: mb.unit_id},
      {k: "Function Code",  v: `${mb.function_code} — ${mb.function_name}`},
      ...Object.entries(mb.details || {}).map(([k, v]) => ({k, v})),
    ];
    if (mb.is_write) mbFields.push({k: "⚠ WARNING", v: "WRITE command — modifies PLC state"});
    mbFields.forEach(f => {
      const row = document.createElement("div");
      row.className = "pkt-field";
      const valColor = mb.is_write && f.k === "⚠ WARNING" ? "var(--red)" : "";
      row.innerHTML = `<span class="pkt-fk">${escHtml(String(f.k))}:</span><span class="pkt-fv" style="color:${valColor}">${escHtml(String(f.v))}</span>`;
      fields.appendChild(row);
    });
    mbDiv.appendChild(hdr);
    mbDiv.appendChild(fields);
    pktTree.appendChild(mbDiv);
  }

  // MQTT section
  if (p.mqtt) {
    const mq = p.mqtt;
    const mqDiv = document.createElement("div");
    mqDiv.className = "pkt-layer";
    const hdr = document.createElement("div");
    hdr.className = "pkt-layer-header";
    const mqColor = mq.type_name === "PUBLISH" ? "var(--accent)" :
                    mq.type_name === "CONNECT" ? "var(--green)" :
                    mq.type_name.startsWith("DISCONNECT") ? "var(--red)" : "var(--text)";
    hdr.innerHTML = `<span class="pkt-arrow">&#9660;</span> <span style="color:${mqColor}">MQTT — ${escHtml(mq.type_name)}</span>`;
    hdr.addEventListener("click", () => mqDiv.classList.toggle("collapsed"));
    const fields = document.createElement("div");
    fields.className = "pkt-layer-fields";
    const mqFields = [
      {k: "Message Type", v: `${mq.type} (${mq.type_name})`},
      {k: "QoS Level",    v: mq.qos},
      {k: "Retain",       v: mq.retain ? "Yes" : "No"},
      ...Object.entries(mq.details || {}).map(([k, v]) => ({k, v})),
    ];
    mqFields.forEach(f => {
      const row = document.createElement("div");
      row.className = "pkt-field";
      row.innerHTML = `<span class="pkt-fk">${escHtml(String(f.k))}:</span><span class="pkt-fv">${escHtml(String(f.v))}</span>`;
      fields.appendChild(row);
    });
    mqDiv.appendChild(hdr);
    mqDiv.appendChild(fields);
    pktTree.appendChild(mqDiv);
  }

  // CoAP section
  if (p.coap) {
    const cp = p.coap;
    const cpDiv = document.createElement("div");
    cpDiv.className = "pkt-layer";
    const hdr = document.createElement("div");
    hdr.className = "pkt-layer-header";
    const cpColor = cp.is_request ? "var(--accent)" : "var(--green)";
    hdr.innerHTML = `<span class="pkt-arrow">&#9660;</span> <span style="color:${cpColor}">CoAP — ${escHtml(cp.code_name)}</span>`;
    hdr.addEventListener("click", () => cpDiv.classList.toggle("collapsed"));
    const fields = document.createElement("div");
    fields.className = "pkt-layer-fields";
    const cpFields = [
      {k: "Type",       v: cp.type},
      {k: "Code",       v: `${cp.code} (${cp.code_name})`},
      {k: "Message ID", v: cp.message_id},
      ...Object.entries(cp.details || {}).map(([k, v]) => ({k, v})),
    ];
    cpFields.forEach(f => {
      const row = document.createElement("div");
      row.className = "pkt-field";
      row.innerHTML = `<span class="pkt-fk">${escHtml(String(f.k))}:</span><span class="pkt-fv">${escHtml(String(f.v))}</span>`;
      fields.appendChild(row);
    });
    cpDiv.appendChild(hdr);
    cpDiv.appendChild(fields);
    pktTree.appendChild(cpDiv);
  }

  // DNP3 section
  if (p.dnp3) {
    const dn = p.dnp3;
    const dnDiv = document.createElement("div");
    dnDiv.className = "pkt-layer";
    const hdr = document.createElement("div");
    hdr.className = "pkt-layer-header";
    const dnColor = dn.is_write ? "var(--red)" : dn.is_error ? "var(--yellow)" : "var(--green)";
    hdr.innerHTML = `<span class="pkt-arrow">&#9660;</span> <span style="color:${dnColor}">DNP3</span>`;
    hdr.addEventListener("click", () => dnDiv.classList.toggle("collapsed"));
    const fields = document.createElement("div");
    fields.className = "pkt-layer-fields";
    const dnFields = [
      {k: "Src Address", v: dn.src_address},
      {k: "Dst Address", v: dn.dst_address},
      {k: "Function Code", v: `${dn.function_code} — ${dn.function_name}`},
      ...Object.entries(dn.details || {}).map(([k, v]) => ({k, v})),
    ];
    if (dn.is_write) dnFields.push({k: "⚠ WARNING", v: "CONTROL command — modifies RTU/IED state"});
    dnFields.forEach(f => {
      const row = document.createElement("div");
      row.className = "pkt-field";
      const valColor = dn.is_write && f.k === "⚠ WARNING" ? "var(--red)" : "";
      row.innerHTML = `<span class="pkt-fk">${escHtml(String(f.k))}:</span><span class="pkt-fv" style="color:${valColor}">${escHtml(String(f.v))}</span>`;
      fields.appendChild(row);
    });
    dnDiv.appendChild(hdr);
    dnDiv.appendChild(fields);
    pktTree.appendChild(dnDiv);
  }

  // S7comm section
  if (p.s7comm) {
    const s7 = p.s7comm;
    const s7Div = document.createElement("div");
    s7Div.className = "pkt-layer";
    const hdr = document.createElement("div");
    hdr.className = "pkt-layer-header";
    const s7Color = s7.is_write ? "var(--red)" : s7.is_error ? "var(--yellow)" : "var(--green)";
    hdr.innerHTML = `<span class="pkt-arrow">&#9660;</span> <span style="color:${s7Color}">S7comm</span>`;
    hdr.addEventListener("click", () => s7Div.classList.toggle("collapsed"));
    const fields = document.createElement("div");
    fields.className = "pkt-layer-fields";
    const s7Fields = [
      {k: "ROSCTR", v: `${s7.rosctr} — ${s7.rosctr_name}`},
      {k: "PDU Reference", v: s7.pdu_ref},
      ...(s7.function_code !== null ? [{k: "Function Code", v: `0x${s7.function_code.toString(16).toUpperCase()} — ${s7.function_name}`}] : []),
      ...Object.entries(s7.details || {}).map(([k, v]) => ({k, v})),
    ];
    if (s7.is_write) s7Fields.push({k: "⚠ WARNING", v: "WRITE/CONTROL command — modifies PLC state"});
    s7Fields.forEach(f => {
      const row = document.createElement("div");
      row.className = "pkt-field";
      const valColor = s7.is_write && f.k === "⚠ WARNING" ? "var(--red)" : "";
      row.innerHTML = `<span class="pkt-fk">${escHtml(String(f.k))}:</span><span class="pkt-fv" style="color:${valColor}">${escHtml(String(f.v))}</span>`;
      fields.appendChild(row);
    });
    s7Div.appendChild(hdr);
    s7Div.appendChild(fields);
    pktTree.appendChild(s7Div);
  }

  // EtherNet/IP section
  if (p.enip) {
    const ei = p.enip;
    const eiDiv = document.createElement("div");
    eiDiv.className = "pkt-layer";
    const hdr = document.createElement("div");
    hdr.className = "pkt-layer-header";
    const eiColor = ei.is_write ? "var(--red)" : ei.is_error ? "var(--yellow)" : "var(--green)";
    hdr.innerHTML = `<span class="pkt-arrow">&#9660;</span> <span style="color:${eiColor}">EtherNet/IP</span>`;
    hdr.addEventListener("click", () => eiDiv.classList.toggle("collapsed"));
    const fields = document.createElement("div");
    fields.className = "pkt-layer-fields";
    const eiFields = [
      {k: "Command", v: `${ei.command_name} (0x${ei.command.toString(16).toUpperCase()})`},
      {k: "Session Handle", v: ei.session_handle},
      {k: "Status", v: ei.status === 0 ? "OK" : `Error (${ei.status})`},
    ];
    if (ei.cip_service !== null) {
      eiFields.push({k: "CIP Service", v: `${ei.cip_service_name} (0x${ei.cip_service.toString(16).toUpperCase()})${ei.is_response ? " [Response]" : ""}`});
    }
    if (ei.is_write) eiFields.push({k: "⚠ WARNING", v: "CIP WRITE — modifies controller tag/attribute"});
    eiFields.forEach(f => {
      const row = document.createElement("div");
      row.className = "pkt-field";
      const valColor = ei.is_write && f.k === "⚠ WARNING" ? "var(--red)" : "";
      row.innerHTML = `<span class="pkt-fk">${escHtml(String(f.k))}:</span><span class="pkt-fv" style="color:${valColor}">${escHtml(String(f.v))}</span>`;
      fields.appendChild(row);
    });
    eiDiv.appendChild(hdr);
    eiDiv.appendChild(fields);
    pktTree.appendChild(eiDiv);
  }

  // IEC 60870-5-104 section
  if (p.iec104) {
    const ic = p.iec104;
    const icDiv = document.createElement("div");
    icDiv.className = "pkt-layer";
    const hdr = document.createElement("div");
    hdr.className = "pkt-layer-header";
    const icColor = ic.is_write ? "var(--red)" : ic.is_error ? "var(--yellow)" : "var(--green)";
    hdr.innerHTML = `<span class="pkt-arrow">&#9660;</span> <span style="color:${icColor}">IEC 60870-5-104</span>`;
    hdr.addEventListener("click", () => icDiv.classList.toggle("collapsed"));
    const fields = document.createElement("div");
    fields.className = "pkt-layer-fields";
    const icFields = [
      {k: "Frame Type", v: ic.frame_type + (ic.u_type ? ` (${ic.u_type})` : "")},
    ];
    if (ic.type_id !== null) {
      icFields.push({k: "Type ID", v: `${ic.type_id} — ${ic.type_name}`});
      icFields.push({k: "COT", v: `${ic.cot} — ${ic.cot_name}`});
      if (ic.common_address !== null) icFields.push({k: "Common Address", v: ic.common_address});
      if (ic.details && ic.details.test) icFields.push({k: "Test Flag", v: "true"});
    }
    if (ic.is_write) icFields.push({k: "⚠ WARNING", v: "CONTROL command — activates IED output"});
    icFields.forEach(f => {
      const row = document.createElement("div");
      row.className = "pkt-field";
      const valColor = ic.is_write && f.k === "⚠ WARNING" ? "var(--red)" : "";
      row.innerHTML = `<span class="pkt-fk">${escHtml(String(f.k))}:</span><span class="pkt-fv" style="color:${valColor}">${escHtml(String(f.v))}</span>`;
      fields.appendChild(row);
    });
    icDiv.appendChild(hdr);
    icDiv.appendChild(fields);
    pktTree.appendChild(icDiv);
  }

  // BACnet section
  if (p.bacnet) {
    const bn = p.bacnet;
    const bnDiv = document.createElement("div");
    bnDiv.className = "pkt-layer";
    const hdr = document.createElement("div");
    hdr.className = "pkt-layer-header";
    const bnColor = bn.is_write ? "var(--red)" : bn.is_error ? "var(--yellow)" : "var(--green)";
    hdr.innerHTML = `<span class="pkt-arrow">&#9660;</span> <span style="color:${bnColor}">BACnet/IP</span>`;
    hdr.addEventListener("click", () => bnDiv.classList.toggle("collapsed"));
    const fields = document.createElement("div");
    fields.className = "pkt-layer-fields";
    const bnFields = [
      {k: "BVLC Function", v: bn.bvlc_function_name},
      {k: "PDU Type", v: bn.pdu_type_name},
    ];
    if (bn.service_name !== null) bnFields.push({k: "Service", v: bn.service_name});
    if (bn.invoke_id !== null) bnFields.push({k: "Invoke ID", v: bn.invoke_id});
    if (bn.is_write) bnFields.push({k: "⚠ WARNING", v: "WRITE service — modifies building controller property"});
    bnFields.forEach(f => {
      const row = document.createElement("div");
      row.className = "pkt-field";
      const valColor = bn.is_write && f.k === "⚠ WARNING" ? "var(--red)" : "";
      row.innerHTML = `<span class="pkt-fk">${escHtml(String(f.k))}:</span><span class="pkt-fv" style="color:${valColor}">${escHtml(String(f.v))}</span>`;
      fields.appendChild(row);
    });
    bnDiv.appendChild(hdr);
    bnDiv.appendChild(fields);
    pktTree.appendChild(bnDiv);
  }

  // Hex dump
  const hexStr = p.hex || "";
  if (!hexStr) {
    pktHex.innerHTML = "";
    pktHexEmpty.style.display = "block";
    return;
  }
  pktHexEmpty.style.display = "none";
  const bytes = [];
  for (let i = 0; i < hexStr.length; i += 2) bytes.push(parseInt(hexStr.slice(i, i + 2), 16));
  const ROW = 16;
  let out = "";
  for (let off = 0; off < bytes.length; off += ROW) {
    const chunk = bytes.slice(off, off + ROW);
    const offset = off.toString(16).padStart(4, "0");
    const hex1 = chunk.slice(0, 8).map(b => b.toString(16).padStart(2, "0")).join(" ");
    const hex2 = chunk.slice(8).map(b => b.toString(16).padStart(2, "0")).join(" ");
    const hexPart = (hex1 + (hex2 ? "  " + hex2 : "")).padEnd(49);
    const ascii = chunk.map(b => (b >= 32 && b < 127) ? String.fromCharCode(b) : ".").join("");
    out += `<span class="hx-off">${offset}</span>  <span class="hx-byt">${hexPart}</span><span class="hx-asc">${escHtml(ascii)}</span>\n`;
  }
  pktHex.innerHTML = out;
}

function buildHttpHeadersTable(headers) {
  if (!headers || Object.keys(headers).length === 0) return "";
  let html = `<table class="pkt-http-headers-table">`;
  for (const [k, v] of Object.entries(headers)) {
    html += `<tr><td>${escHtml(k)}</td><td>${escHtml(v)}</td></tr>`;
  }
  html += "</table>";
  return html;
}

function escHtml(s) {
  return String(s).replace(/&/g,"&amp;").replace(/</g,"&lt;").replace(/>/g,"&gt;");
}

/* ── Packet inspector resize handle ──────────────────────────────────────── */
(function () {
  const handle = document.getElementById("pkt-resize-handle");
  let dragging = false, startY = 0, startH = 0;
  handle.addEventListener("mousedown", e => {
    dragging = true; startY = e.clientY; startH = pktInspector.offsetHeight;
    document.body.style.userSelect = "none";
    document.body.style.cursor = "ns-resize";
  });
  document.addEventListener("mousemove", e => {
    if (!dragging) return;
    const newH = Math.max(120, Math.min(startH + (startY - e.clientY), window.innerHeight * 0.75));
    pktInspector.style.height = newH + "px";
    const shift = newH + 16;
    document.querySelectorAll("#graph-controls, #legend").forEach(el => {
      if (graphWrap.classList.contains("pkt-open")) el.style.bottom = shift + "px";
    });
  });
  document.addEventListener("mouseup", () => {
    if (!dragging) return;
    dragging = false;
    document.body.style.userSelect = "";
    document.body.style.cursor = "";
  });
})();

/* ── Connection Table View ───────────────────────────────────────────────── */
function renderConnTable() {
  if (!graphData) return;
  const tbody = document.getElementById("conn-tbody");
  tbody.innerHTML = "";

  let edges = [...graphData.edges];

  // Sort
  edges.sort((a, b) => {
    const av = a[tableSort.col] || 0;
    const bv = b[tableSort.col] || 0;
    if (typeof av === "string") return tableSort.dir === "asc" ? av.localeCompare(bv) : bv.localeCompare(av);
    return tableSort.dir === "asc" ? av - bv : bv - av;
  });

  // Apply protocol + host type filters
  const nodeMap = {};
  graphData.nodes.forEach(n => nodeMap[n.ip] = n);

  edges.forEach(e => {
    const srcNode = nodeMap[e.source];
    const dstNode = nodeMap[e.target];
    const protoOk = e.protocols.some(p => activeProtos.has(p));
    const typeOk = (!srcNode || activeTypes.has(srcNode.host_type)) &&
                   (!dstNode || activeTypes.has(dstNode.host_type));
    const searchOk = !searchTerm ||
      e.source.includes(searchTerm) || e.target.includes(searchTerm);

    const tr = document.createElement("tr");
    if (!protoOk || !typeOk || !searchOk) tr.className = "ct-faded";

    const duration = (e.first_seen != null && e.last_seen != null)
      ? (e.last_seen - e.first_seen).toFixed(3) + "s"
      : "—";

    tr.innerHTML = `
      <td title="${e.source}">${e.source}</td>
      <td title="${e.target}">${e.target}</td>
      <td>${e.protocols.join(", ")}</td>
      <td>${fmtNum(e.packet_count)}</td>
      <td>${fmtBytes(e.bytes)}</td>
      <td>${e.ports.slice(0,8).join(", ")}</td>
      <td>${duration}</td>
    `;
    tr.addEventListener("click", () => {
      if (currentView === "table") {
        // Switch to graph + open inspector
        setView("graph");
        setTimeout(() => openPktInspector(e.source, e.target), 100);
      } else {
        openPktInspector(e.source, e.target);
      }
    });
    tbody.appendChild(tr);
  });
}

// Table sort click handlers
document.querySelectorAll("#conn-table th.sortable").forEach(th => {
  th.addEventListener("click", () => {
    const col = th.dataset.col;
    if (tableSort.col === col) {
      tableSort.dir = tableSort.dir === "asc" ? "desc" : "asc";
    } else {
      tableSort.col = col;
      tableSort.dir = "desc";
    }
    document.querySelectorAll("#conn-table th").forEach(h => {
      h.classList.remove("sort-asc", "sort-desc");
    });
    th.classList.add(tableSort.dir === "asc" ? "sort-asc" : "sort-desc");
    renderConnTable();
  });
});

/* ── OT Map Edit State ───────────────────────────────────────────────────── */
let otEditMode   = false;
let otFilterAll  = false;       // bypass activeTypes filter in OT map
let otLaneY      = {};          // level → y start (promoted from renderOTMap)
let otLaneH      = {};          // level → height  (promoted from renderOTMap)
let otZoom       = null;        // d3 zoom behavior (created once)
let otZoomState  = d3.zoomIdentity; // persists across re-renders

const otOverrides  = {};        // nodeId → override purdue_level
const otRiskLabels = {};        // nodeId → { label, note }
const otAddedNodes = [];        // manually added nodes
const otRemovedIds = new Set(); // manually removed node IDs

const OT_RISK_COLORS = {
  Critical: "#f85149", High: "#ff8c00", Medium: "#d29922",
  Low:      "#3fb950", Info: "#58a6ff",
};

/* ── OT Map View (Purdue Model) ──────────────────────────────────────────── */
const PURDUE_LEVELS = [
  { level: 5,   label: "L5 — Enterprise/Internet", types: new Set([]) /* external IPs via country */ },
  { level: 4,   label: "L4 — Business Logistics",  types: new Set(["Windows Host","Web Server","Mail Server","Directory Server","Database Server"]) },
  { level: 3.5, label: "L3.5 — Industrial DMZ",    types: new Set(["VPN Gateway","Security Tool","Remote Desktop"]) },
  { level: 3,   label: "L3 — Supervisory / Ops",   types: new Set(["SCADA Server","Historian","Engineering Workstation"]) },
  { level: 2,   label: "L2 — Control / HMI",       types: new Set(["HMI","DCS"]) },
  { level: 1,   label: "L1 — PLC / RTU",           types: new Set(["PLC","RTU","IED","Building Controller"]) },
  { level: 0,   label: "L0 — Field Devices",       types: new Set(["Field Device","IoT Sensor","Smart Meter"]) },
  { level: -1,  label: "? — Unclassified",          types: new Set([]) /* catch-all */ },
];
const LEVEL_COLORS = {
  5: "#1a2a4a", 4: "#1f3a5f", 3.5: "#3a2800",
  3: "#2d5a27", 2: "#5a4a00", 1: "#5a1a00", 0: "#2a1a3a", [-1]: "#2a2a2a",
};
const PURDUE_DESC = {
  5:   "Corporate network, internet, cloud services",
  4:   "ERP, business servers, IT management",
  3.5: "Firewall/gateway buffer between OT and IT",
  3:   "Historians, SCADA servers, engineering workstations",
  2:   "HMI, DCS operator consoles",
  1:   "PLCs, RTUs, safety controllers",
  0:   "Sensors, actuators, field instruments",
  [-1]: "Devices not yet classified to a Purdue level",
};

// Zone groupings for the left-margin bracket labels
const PURDUE_ZONES = [
  { name: "IT Zone",        levels: new Set([5, 4]),    color: "#2a6aac" },
  { name: "Industrial DMZ", levels: new Set([3.5]),     color: "#c87000" },
  { name: "OT Zone",        levels: new Set([3,2,1,0]), color: "#4a8a1a" },
];

function purdueLevel(node) {
  if (node.country || (node.geo && node.geo.country_code)) return 5;
  for (const row of PURDUE_LEVELS) {
    if (row.types.has(node.host_type)) {
      // L4 hosts with OT protocol evidence are demoted to L3 (supervisory)
      if (row.level === 4) {
        const hasOtEvidence = (node.ot_role && node.ot_role !== "unknown")
          || (node.modbus_unit_ids && node.modbus_unit_ids.length > 0)
          || (node.dnp3_addresses && node.dnp3_addresses.length > 0);
        return hasOtEvidence ? 3 : 4;
      }
      return row.level;
    }
  }
  return -1;
}

function renderOTMap(data) {
  if (!data) return;
  const svg = document.getElementById("ot-map-svg");
  svg.innerHTML = "";

  const W = svg.parentElement.clientWidth || 900;
  const ns = "http://www.w3.org/2000/svg";

  // Layout constants
  const ZONE_HEADER_H = 28;
  const LANE_H_BASE   = 76;
  const ROW_H         = 58;
  const MAX_PER_ROW   = 8;
  const LABEL_W       = 210;
  const nodeR         = 16;

  // Zone layout — order defines top-to-bottom rendering
  const ZONE_LAYOUT = [
    { name: "IT Zone",        desc: "Enterprise & business network",        color: "#2a6aac", levels: [5, 4]      },
    { name: "Industrial DMZ", desc: "Firewall/gateway buffer between zones", color: "#c87000", levels: [3.5]      },
    { name: "OT Zone",        desc: "Operational Technology (ICS / SCADA)", color: "#4a8a1a", levels: [3, 2, 1, 0]},
    { name: "Unclassified",   desc: "Devices not yet assigned to a level",  color: "#555",    levels: [-1]       },
  ];

  // Zone membership for cross-zone detection (zone boundary crossing = security concern)
  const nodeZone = (lvl) => {
    if (lvl >= 4) return "IT";
    if (lvl === 3.5) return "DMZ";
    if (lvl >= 0 && lvl <= 3) return "OT";
    return null;
  };

  // ── Effective node set (edit overrides + optional activeTypes filter) ──────
  let baseNodes = data.nodes.filter(n => !otRemovedIds.has(n.id));
  if (!otFilterAll && activeTypes.size > 0) {
    baseNodes = baseNodes.filter(n => activeTypes.has(n.host_type));
  }
  const effectiveNodes = [...baseNodes, ...otAddedNodes];

  // ── Compute node levels ────────────────────────────────────────────────────
  const nodeLevel = {};
  effectiveNodes.forEach(n => {
    nodeLevel[n.id] = (otOverrides[n.id] !== undefined)
      ? otOverrides[n.id]
      : (n.purdue_level !== undefined ? n.purdue_level : purdueLevel(n));
  });

  // ── Identify bridge nodes ─────────────────────────────────────────────────
  const bridgeIds = new Set();
  effectiveNodes.forEach(n => {
    const peerLevels = new Set();
    data.edges.forEach(e => {
      if (e.source === n.id) peerLevels.add(nodeLevel[e.target] ?? -1);
      if (e.target === n.id) peerLevels.add(nodeLevel[e.source] ?? -1);
    });
    const hasOT = [...peerLevels].some(l => l >= 0 && l <= 3);
    const hasIT = [...peerLevels].some(l => l >= 4 && l <= 5);
    if (hasOT && hasIT) bridgeIds.add(n.id);
  });

  // ── Build anomaly set from existing global anomalyNodeIps ─────────────────
  // anomalyNodeIps is populated by buildAnomalyList (global: ip → 'high'|'medium'|'low')
  const anomalyIpSet = new Set(Object.keys(anomalyNodeIps));

  // ── Count cross-zone (security boundary) vs cross-level (same zone) edges ─
  let crossZoneCount = 0;   // crosses IT↔DMZ, DMZ↔OT, IT↔OT boundaries
  let crossLevelCount = 0;  // different levels but same zone (e.g., L4↔L3... wait L4 is IT L3 is OT)
  data.edges.forEach(e => {
    const sl = nodeLevel[e.source] ?? -1, tl = nodeLevel[e.target] ?? -1;
    if (sl < 0 || tl < 0 || sl === tl) return;
    const sz = nodeZone(sl), tz = nodeZone(tl);
    if (sz && tz && sz !== tz) crossZoneCount++;
    else if (sz && tz && sz === tz && sl !== tl) crossLevelCount++;
  });
  const bridgeCount = bridgeIds.size;
  const anomalyCount = effectiveNodes.filter(n => anomalyIpSet.has(n.ip)).length;

  // ── Stats chips in header ─────────────────────────────────────────────────
  function chip(text, color) {
    return `<span class="ot-stat-chip" style="color:${color};border-color:${color}55;background:${color}18">${text}</span>`;
  }
  const activeLevelSet = new Set(effectiveNodes.map(n => nodeLevel[n.id] ?? -1).filter(l => l >= 0));
  document.getElementById("ot-stats-bar").innerHTML = [
    chip(`${effectiveNodes.length} devices`, "#58a6ff"),
    chip(`${activeLevelSet.size} active levels`, "#8b949e"),
    crossZoneCount > 0 ? chip(`⚠ ${crossZoneCount} cross-zone`, "#ff8c00") : chip("✓ no cross-zone", "#3fb950"),
    crossLevelCount > 0 ? chip(`${crossLevelCount} cross-level`, "#d29922") : null,
    bridgeCount > 0 ? chip(`⚠ ${bridgeCount} bridge${bridgeCount > 1 ? "s" : ""}`, "#ff6b35") : null,
    anomalyCount > 0 ? chip(`⚠ ${anomalyCount} anomal${anomalyCount > 1 ? "ies" : "y"}`, "#f85149") : null,
    !otFilterAll && activeTypes.size > 0 ? chip("filtered", "#8b949e") : null,
  ].filter(Boolean).join("");
  document.getElementById("ot-zone-count").textContent =
    crossZoneCount > 0 || bridgeCount > 0
      ? `Cross-zone traffic detected — review highlighted connections for security violations.`
      : "All connections stay within their security zone.";

  // ── Pre-pass: compute dynamic lane heights and Y positions ────────────────
  // Unclassified zone is skipped entirely if it has no devices
  const hasUnclassified = effectiveNodes.some(n => (nodeLevel[n.id] ?? -1) === -1);
  const activeZoneLayout = ZONE_LAYOUT.filter(z =>
    z.name !== "Unclassified" || hasUnclassified
  );

  const laneH = {};
  const laneY = {};
  const zoneHeaderY = {};
  let currentY = 0;
  activeZoneLayout.forEach(zone => {
    zoneHeaderY[zone.name] = currentY;
    currentY += ZONE_HEADER_H;
    zone.levels.forEach(lvl => {
      const count = effectiveNodes.filter(n => (nodeLevel[n.id] ?? -1) === lvl).length;
      const numRows = Math.max(1, Math.ceil(count / MAX_PER_ROW));
      laneH[lvl] = LANE_H_BASE + (numRows - 1) * ROW_H;
      laneY[lvl] = currentY;
      currentY += laneH[lvl];
    });
  });
  const totalH = currentY || 400;
  otLaneY = laneY;
  otLaneH = laneH;

  // Detect which lanes have a high-severity anomaly (for tinting)
  const laneHasHighAnomaly = {};
  effectiveNodes.forEach(n => {
    if (anomalyNodeIps[n.ip] === "high") {
      const lvl = nodeLevel[n.id] ?? -1;
      laneHasHighAnomaly[lvl] = true;
    }
  });

  svg.setAttribute("viewBox", `0 0 ${W} ${totalH}`);
  svg.setAttribute("width", W);
  svg.setAttribute("height", totalH);
  svg.style.height = totalH + "px";

  // ── SVG defs: arrow marker for cross-zone edges ───────────────────────────
  const defs = document.createElementNS(ns, "defs");
  defs.innerHTML = `<marker id="ot-arrow" markerWidth="7" markerHeight="7" refX="5.5" refY="3.5" orient="auto">
    <path d="M0,0 L0,7 L7,3.5 z" fill="#ff8c00" opacity="0.9"/>
  </marker>`;
  svg.appendChild(defs);

  // ── Zoom group wraps all rendered content ─────────────────────────────────
  const zoomGroup = document.createElementNS(ns, "g");
  zoomGroup.setAttribute("id", "ot-zoom-group");
  svg.appendChild(zoomGroup);

  // ── SVG layers (inside zoom group) ───────────────────────────────────────
  const bgLayer   = document.createElementNS(ns, "g");
  const edgeLayer = document.createElementNS(ns, "g");
  const nodeLayer = document.createElementNS(ns, "g");
  zoomGroup.appendChild(bgLayer);
  zoomGroup.appendChild(edgeLayer);
  zoomGroup.appendChild(nodeLayer);

  // ── Draw zone header strips ───────────────────────────────────────────────
  activeZoneLayout.forEach(zone => {
    const y = zoneHeaderY[zone.name];

    const strip = document.createElementNS(ns, "rect");
    strip.setAttribute("x", 0); strip.setAttribute("y", y);
    strip.setAttribute("width", W); strip.setAttribute("height", ZONE_HEADER_H);
    strip.setAttribute("fill", zone.color); strip.setAttribute("opacity", "0.2");
    bgLayer.appendChild(strip);

    const accent = document.createElementNS(ns, "rect");
    accent.setAttribute("x", 0); accent.setAttribute("y", y);
    accent.setAttribute("width", 4); accent.setAttribute("height", ZONE_HEADER_H);
    accent.setAttribute("fill", zone.color);
    bgLayer.appendChild(accent);

    const nameEl = document.createElementNS(ns, "text");
    nameEl.setAttribute("x", 12); nameEl.setAttribute("y", y + 12);
    nameEl.setAttribute("fill", "#eee"); nameEl.setAttribute("font-size", "11");
    nameEl.setAttribute("font-weight", "700"); nameEl.setAttribute("font-family", "var(--font-mono)");
    nameEl.textContent = zone.name.toUpperCase();
    bgLayer.appendChild(nameEl);

    const descEl = document.createElementNS(ns, "text");
    descEl.setAttribute("x", 12); descEl.setAttribute("y", y + 23);
    descEl.setAttribute("fill", "#888"); descEl.setAttribute("font-size", "9");
    descEl.setAttribute("font-family", "var(--font-mono)");
    descEl.textContent = zone.desc;
    bgLayer.appendChild(descEl);
  });

  // ── Draw lane backgrounds + headers ───────────────────────────────────────
  // Only render lanes that are part of the active zone layout
  const activeLevels = new Set(activeZoneLayout.flatMap(z => z.levels));
  PURDUE_LEVELS.filter(row => activeLevels.has(row.level)).forEach(row => {
    const y = laneY[row.level];
    const h = laneH[row.level];
    if (y === undefined) return;
    const laneNodes = effectiveNodes.filter(n => (nodeLevel[n.id] ?? -1) === row.level);
    const hasAnomaly = laneHasHighAnomaly[row.level];

    // Lane background
    const bg = document.createElementNS(ns, "rect");
    bg.setAttribute("x", 0); bg.setAttribute("y", y);
    bg.setAttribute("width", W); bg.setAttribute("height", h);
    bg.setAttribute("fill", LEVEL_COLORS[row.level]); bg.setAttribute("opacity", "0.28");
    bgLayer.appendChild(bg);

    // High-anomaly tint overlay
    if (hasAnomaly) {
      const tint = document.createElementNS(ns, "rect");
      tint.setAttribute("x", 0); tint.setAttribute("y", y);
      tint.setAttribute("width", W); tint.setAttribute("height", h);
      tint.setAttribute("fill", "#f85149"); tint.setAttribute("opacity", "0.06");
      bgLayer.appendChild(tint);
    }

    // Vertical divider between label area and node canvas
    const divider = document.createElementNS(ns, "line");
    divider.setAttribute("x1", LABEL_W); divider.setAttribute("y1", y);
    divider.setAttribute("x2", LABEL_W); divider.setAttribute("y2", y + h);
    divider.setAttribute("stroke", "#333"); divider.setAttribute("stroke-width", "1");
    bgLayer.appendChild(divider);

    // Level label — with Purdue description tooltip on hover
    const lbl = document.createElementNS(ns, "text");
    lbl.setAttribute("x", 8); lbl.setAttribute("y", y + 14);
    lbl.setAttribute("fill", "#ddd"); lbl.setAttribute("font-size", "11");
    lbl.setAttribute("font-weight", "600"); lbl.setAttribute("font-family", "var(--font-mono)");
    lbl.textContent = row.label;
    lbl.style.cursor = "help";
    lbl.addEventListener("mouseenter", (ev) => {
      tooltip.innerHTML = `<div class="tip-ip" style="font-size:11px">${row.label}</div>
        <div class="tip-type">${PURDUE_DESC[row.level]}</div>`;
      tooltip.classList.add("visible");
      positionTooltip(ev);
    });
    lbl.addEventListener("mousemove", positionTooltip);
    lbl.addEventListener("mouseleave", hideTooltip);
    bgLayer.appendChild(lbl);

    // Description subtitle
    const desc = document.createElementNS(ns, "text");
    desc.setAttribute("x", 8); desc.setAttribute("y", y + 27);
    desc.setAttribute("fill", "#666"); desc.setAttribute("font-size", "8.5");
    desc.setAttribute("font-family", "var(--font-mono)");
    desc.textContent = PURDUE_DESC[row.level] || "";
    bgLayer.appendChild(desc);

    // Device count
    if (laneNodes.length > 0) {
      const cnt = document.createElementNS(ns, "text");
      cnt.setAttribute("x", LABEL_W - 6); cnt.setAttribute("y", y + 14);
      cnt.setAttribute("fill", "#8b949e"); cnt.setAttribute("font-size", "9");
      cnt.setAttribute("font-family", "var(--font-mono)"); cnt.setAttribute("text-anchor", "end");
      cnt.textContent = `${laneNodes.length} device${laneNodes.length !== 1 ? "s" : ""}`;
      bgLayer.appendChild(cnt);
    }

    // Empty lane placeholder
    if (laneNodes.length === 0) {
      const ph = document.createElementNS(ns, "text");
      ph.setAttribute("x", LABEL_W + (W - LABEL_W) / 2); ph.setAttribute("y", y + h / 2 + 4);
      ph.setAttribute("fill", "#444"); ph.setAttribute("font-size", "11");
      ph.setAttribute("font-family", "var(--font-mono)"); ph.setAttribute("text-anchor", "middle");
      ph.setAttribute("font-style", "italic");
      ph.textContent = "no devices detected";
      bgLayer.appendChild(ph);
    }
  });

  // ── Position nodes (multi-row) ────────────────────────────────────────────
  const nodePos = {};
  PURDUE_LEVELS.filter(row => activeLevels.has(row.level)).forEach(row => {
    const laneNodes = effectiveNodes.filter(n => (nodeLevel[n.id] ?? -1) === row.level);
    if (laneY[row.level] === undefined) return;
    const usableW = W - LABEL_W - 24;
    const yTop = laneY[row.level] + 38;
    laneNodes.forEach((n, j) => {
      const rowIdx = Math.floor(j / MAX_PER_ROW);
      const colIdx = j % MAX_PER_ROW;
      const nodesInRow = Math.min(MAX_PER_ROW, laneNodes.length - rowIdx * MAX_PER_ROW);
      const x = LABEL_W + 12 + (colIdx + 0.5) * (usableW / nodesInRow);
      const y = yTop + nodeR + rowIdx * ROW_H;
      nodePos[n.id] = { x, y };
    });
  });

  // ── Draw edges: traffic-weighted, S-bend bezier curves ───────────────────
  // Build nodeEdgeMap for hover highlighting
  const nodeEdgeMap = {};   // nodeId → [pathElement]
  const allEdgePaths = [];  // all drawn path elements

  // Log-scale edge width matching force-graph edgeWidth()
  const maxPkt = Math.max(1, ...data.edges.map(e => e.packet_count || 1));
  const edgeW = (pkt) => 1 + Math.log1p(pkt) / Math.log1p(maxPkt) * 3;

  data.edges.forEach(e => {
    const sp = nodePos[e.source], tp = nodePos[e.target];
    if (!sp || !tp) return;
    const sl = nodeLevel[e.source] ?? -1, tl = nodeLevel[e.target] ?? -1;
    const sz = nodeZone(sl), tz = nodeZone(tl);
    const isCrossZone = sz && tz && sz !== tz;

    const rawDy = tp.y - sp.y;
    const sign = rawDy >= 0 ? 1 : -1;
    const endX = tp.x, endY = tp.y - sign * (nodeR + 3);
    const midY = (sp.y + endY) / 2;

    const path = document.createElementNS(ns, "path");
    path.setAttribute("d", `M ${sp.x} ${sp.y} C ${sp.x} ${midY}, ${endX} ${midY}, ${endX} ${endY}`);
    path.setAttribute("fill", "none");
    path.setAttribute("stroke", isCrossZone ? "#ff8c00" : "#555");
    path.setAttribute("stroke-width", edgeW(e.packet_count || 1) * (isCrossZone ? 1.5 : 1));
    path.setAttribute("opacity", isCrossZone ? "0.85" : "0.45");
    if (isCrossZone) path.setAttribute("marker-end", "url(#ot-arrow)");

    // Edge tooltip
    path.addEventListener("mouseenter", (ev) => {
      const otR = e.ot_reads || 0, otW = e.ot_writes || 0;
      tooltip.innerHTML = `
        <div class="tip-ip" style="font-size:11px">${e.source} ↔ ${e.target}</div>
        <div class="tip-type">${fmtNum(e.packet_count || 0)} pkts · ${fmtBytes(e.bytes || 0)}</div>
        ${otR || otW ? `<div class="tip-type">OT reads: ${otR} · writes: ${otW}</div>` : ""}
        ${isCrossZone ? `<div style="color:#ff8c00;font-size:10px;margin-top:3px">⚠ Cross-zone: ${sz}→${tz}</div>` : ""}
      `;
      tooltip.classList.add("visible");
      positionTooltip(ev);
    });
    path.addEventListener("mousemove", positionTooltip);
    path.addEventListener("mouseleave", hideTooltip);

    edgeLayer.appendChild(path);
    allEdgePaths.push({ path, src: e.source, tgt: e.target });

    if (!nodeEdgeMap[e.source]) nodeEdgeMap[e.source] = [];
    if (!nodeEdgeMap[e.target]) nodeEdgeMap[e.target] = [];
    nodeEdgeMap[e.source].push(path);
    nodeEdgeMap[e.target].push(path);
  });

  // ── Draw nodes ────────────────────────────────────────────────────────────
  effectiveNodes.forEach(n => {
    const pos = nodePos[n.id];
    if (!pos) return;
    const lvl = nodeLevel[n.id] ?? -1;
    const levelRow = PURDUE_LEVELS.find(r => r.level === lvl);
    const isBridge = bridgeIds.has(n.id);
    const hasAnomaly = anomalyIpSet.has(n.ip);
    const anomalySev = anomalyNodeIps[n.ip];
    const connCount = data.edges.filter(e => e.source === n.id || e.target === n.id).length;
    const risk = otRiskLabels[n.id];

    const g = document.createElementNS(ns, "g");
    g.setAttribute("transform", `translate(${pos.x},${pos.y})`);
    g.style.cursor = "pointer";

    // Risk ring (outermost)
    if (risk?.label) {
      const rRing = document.createElementNS(ns, "circle");
      rRing.setAttribute("r", nodeR + (isBridge ? 12 : 6));
      rRing.setAttribute("fill",         OT_RISK_COLORS[risk.label] + "22");
      rRing.setAttribute("stroke",       OT_RISK_COLORS[risk.label]);
      rRing.setAttribute("stroke-width", "2");
      g.appendChild(rRing);
    }

    // Bridge ring
    if (isBridge) {
      const ring = document.createElementNS(ns, "circle");
      ring.setAttribute("r", nodeR + 6);
      ring.setAttribute("fill", "none");
      ring.setAttribute("stroke", "#ff8c00");
      ring.setAttribute("stroke-width", "2.5");
      ring.setAttribute("class", "bridge-ring");
      g.appendChild(ring);
    }

    const circle = document.createElementNS(ns, "circle");
    circle.setAttribute("r", nodeR);
    circle.setAttribute("fill", hostColor(n.host_type));
    circle.setAttribute("stroke", otEditMode ? "#aaa" : "#fff");
    circle.setAttribute("stroke-width", "1.5");
    g.appendChild(circle);

    const icon = document.createElementNS(ns, "text");
    icon.setAttribute("text-anchor", "middle"); icon.setAttribute("dy", "0.35em");
    icon.setAttribute("font-size", "12");
    icon.textContent = hostIcon(n.host_type);
    g.appendChild(icon);

    const lbl = document.createElementNS(ns, "text");
    lbl.setAttribute("text-anchor", "middle"); lbl.setAttribute("dy", nodeR + 12);
    lbl.setAttribute("fill", "#bbb"); lbl.setAttribute("font-size", "9");
    lbl.setAttribute("font-family", "var(--font-mono)");
    lbl.textContent = n.hostname || n.ip;
    g.appendChild(lbl);

    // Risk badge below label
    if (risk?.label) {
      const badge = document.createElementNS(ns, "text");
      badge.setAttribute("text-anchor", "middle"); badge.setAttribute("dy", nodeR + 24);
      badge.setAttribute("fill", OT_RISK_COLORS[risk.label]);
      badge.setAttribute("font-size", "8"); badge.setAttribute("font-weight", "700");
      badge.setAttribute("font-family", "var(--font-mono)");
      badge.textContent = risk.label.toUpperCase();
      g.appendChild(badge);
    }

    // Anomaly badge (! circle, top-right of node)
    if (hasAnomaly && !risk?.label) {
      const badgeR = 6;
      const badgeCx = nodeR - 1, badgeCy = -(nodeR - 1);
      const badgeColor = anomalySev === "high" ? "#f85149" : anomalySev === "medium" ? "#d29922" : "#58a6ff";
      const bc = document.createElementNS(ns, "circle");
      bc.setAttribute("cx", badgeCx); bc.setAttribute("cy", badgeCy);
      bc.setAttribute("r", badgeR); bc.setAttribute("fill", badgeColor);
      bc.setAttribute("stroke", "#0d1117"); bc.setAttribute("stroke-width", "1.5");
      g.appendChild(bc);
      const bt = document.createElementNS(ns, "text");
      bt.setAttribute("x", badgeCx); bt.setAttribute("y", badgeCy);
      bt.setAttribute("text-anchor", "middle"); bt.setAttribute("dominant-baseline", "central");
      bt.setAttribute("font-size", "8"); bt.setAttribute("font-weight", "700");
      bt.setAttribute("fill", "#fff"); bt.setAttribute("pointer-events", "none");
      bt.textContent = "!";
      g.appendChild(bt);
    }

    // Edit mode: delete "×" button
    if (otEditMode) {
      const del = document.createElementNS(ns, "text");
      del.setAttribute("x", nodeR - 1); del.setAttribute("y", -nodeR + 1);
      del.setAttribute("fill", "#f85149"); del.setAttribute("font-size", "13");
      del.setAttribute("font-weight", "700"); del.setAttribute("text-anchor", "middle");
      del.setAttribute("dominant-baseline", "middle");
      del.style.cursor = "pointer";
      del.textContent = "×";
      del.addEventListener("click", e => {
        e.stopPropagation();
        otRemovedIds.add(n.id);
        const ai = otAddedNodes.findIndex(a => a.id === n.id);
        if (ai !== -1) otAddedNodes.splice(ai, 1);
        renderOTMap(data);
      });
      g.appendChild(del);
    }

    // Custom tooltip (replaces native SVG <title>)
    g.addEventListener("mouseenter", (ev) => {
      // Highlight connected edges, dim others
      if (allEdgePaths.length > 0) {
        const connectedPaths = new Set(nodeEdgeMap[n.id] || []);
        allEdgePaths.forEach(({ path }) => {
          path.style.opacity = connectedPaths.has(path) ? "1" : "0.08";
        });
      }
      if (!otEditMode) g.setAttribute("transform", `translate(${pos.x},${pos.y}) scale(1.1)`);

      const levelLabel = levelRow ? levelRow.label : "Unclassified";
      const anomalyLine = anomalySev
        ? `<div style="color:${anomalySev === "high" ? "var(--red)" : anomalySev === "medium" ? "var(--yellow)" : "var(--accent)"};margin-top:3px;font-size:10px">⚠ ${anomalySev.toUpperCase()} anomaly</div>`
        : "";
      tooltip.innerHTML = `
        <div class="tip-ip">${n.ip}${n.hostname ? `<span style="color:var(--text2)"> (${escHtml(n.hostname)})</span>` : ""}</div>
        <div class="tip-type">${n.host_type} · ${levelLabel}</div>
        ${n.protocols.length ? `<div class="tip-proto">${n.protocols.slice(0,6).map(p => `<span style="color:${PROTO_COLORS[p]||'#aaa'}">${p}</span>`).join(" · ")}</div>` : ""}
        <div class="tip-type" style="margin-top:4px">${connCount} connection${connCount !== 1 ? "s" : ""}${isBridge ? " · <span style='color:#ff8c00'>⚠ bridge</span>" : ""}</div>
        ${risk?.label ? `<div style="color:${OT_RISK_COLORS[risk.label]};font-size:10px">Risk: ${risk.label}${risk.note ? " — " + risk.note : ""}</div>` : ""}
        ${anomalyLine}
      `;
      tooltip.classList.add("visible");
      positionTooltip(ev);
    });
    g.addEventListener("mousemove", positionTooltip);
    g.addEventListener("mouseleave", () => {
      g.setAttribute("transform", `translate(${pos.x},${pos.y})`);
      // Restore all edge opacities
      allEdgePaths.forEach(({ path, src, tgt }) => {
        const sl = nodeLevel[src] ?? -1, tl = nodeLevel[tgt] ?? -1;
        const sz = nodeZone(sl), tz = nodeZone(tl);
        const isCross = sz && tz && sz !== tz;
        path.style.opacity = isCross ? "0.85" : "0.45";
      });
      hideTooltip();
    });

    // Click: risk panel in edit mode, detail panel otherwise
    g.addEventListener("click", e => {
      if (otEditMode) { e.stopPropagation(); showOTRiskPanel(n, pos, svg); }
      else { selectedNode = n; showDetailPanel(n); detailPanel.classList.add("open"); }
    });

    // Drag to reclassify (edit mode only)
    if (otEditMode) {
      g.addEventListener("mousedown", e => startOTDrag(e, n, pos, svg, zoomGroup));
    }

    nodeLayer.appendChild(g);
  });

  // ── Attach D3 zoom ───────────────────────────────────────────────────────
  if (!otZoom) {
    otZoom = d3.zoom()
      .scaleExtent([0.15, 6])
      .filter(event => {
        // Ctrl+wheel zooms; plain wheel scrolls the container; drag pans
        if (event.type === "wheel") return event.ctrlKey || event.metaKey;
        return !event.button;
      })
      .on("zoom", (event) => {
        otZoomState = event.transform;
        const zg = document.getElementById("ot-zoom-group");
        if (zg) d3.select(zg).attr("transform", event.transform);
      });
  }
  d3.select(svg).call(otZoom);
  d3.select(svg).call(otZoom.transform, otZoomState);

  // ── Render legend ─────────────────────────────────────────────────────────
  renderOTLegend();
}

/* ── OT Map legend ───────────────────────────────────────────────────────── */
function renderOTLegend() {
  const header = document.getElementById("ot-map-header");
  let legend = document.getElementById("ot-legend");
  if (!legend) {
    legend = document.createElement("div");
    legend.id = "ot-legend";
    header.appendChild(legend);
  }
  const zoneSwatches = [
    { label: "IT Zone",   color: "#2a6aac" },
    { label: "Ind. DMZ",  color: "#c87000" },
    { label: "OT Zone",   color: "#4a8a1a" },
  ];
  const riskDots = Object.entries(OT_RISK_COLORS).map(([k, c]) =>
    `<span class="ot-legend-group"><span class="ot-legend-dot" style="background:${c}"></span>${k}</span>`
  ).join("");
  const zoneHtml = zoneSwatches.map(s =>
    `<span class="ot-legend-group"><span class="ot-legend-swatch" style="background:${s.color}44;border:1px solid ${s.color}"></span>${s.label}</span>`
  ).join("");
  legend.innerHTML = `
    <span style="font-size:9px;color:var(--text2);font-family:var(--font-mono);margin-right:4px">Zones:</span>${zoneHtml}
    <span style="font-size:9px;color:var(--text2);font-family:var(--font-mono);margin:0 4px">Risk:</span>${riskDots}
    <span class="ot-legend-group"><svg width="22" height="10"><circle cx="5" cy="5" r="4" fill="none" stroke="#ff8c00" stroke-width="1.5"/></svg>bridge</span>
    <span class="ot-legend-group"><svg width="28" height="10"><line x1="0" y1="5" x2="28" y2="5" stroke="#ff8c00" stroke-width="1.5"/></svg>cross-zone</span>
    <span class="ot-legend-group"><svg width="28" height="10"><line x1="0" y1="5" x2="28" y2="5" stroke="#555" stroke-width="1.5"/></svg>same-zone</span>
    <span style="font-size:9px;color:var(--text2);font-family:var(--font-mono)">Ctrl+scroll or +/− to zoom · drag to pan</span>
  `;
}

/* ── OT Map drag-to-reclassify ───────────────────────────────────────────── */
function startOTDrag(evt, node, origPos, svgEl, zoomGroup) {
  evt.preventDefault(); evt.stopPropagation();
  const ns = "http://www.w3.org/2000/svg";
  const svgRect = svgEl.getBoundingClientRect();
  const svgW = parseFloat(svgEl.getAttribute("width"))  || svgRect.width;
  const svgH = parseFloat(svgEl.getAttribute("height")) || svgRect.height;
  const scaleX = svgW / svgRect.width;
  const scaleY = svgH / svgRect.height;

  // Ghost and highlight rect live in the zoom group so their coordinates match content space
  const group = zoomGroup || svgEl;

  const ghost = document.createElementNS(ns, "circle");
  ghost.setAttribute("r", 16); ghost.setAttribute("fill", hostColor(node.host_type));
  ghost.setAttribute("opacity", "0.55"); ghost.setAttribute("stroke", "#fff");
  ghost.setAttribute("stroke-width", "2"); ghost.setAttribute("pointer-events", "none");
  group.appendChild(ghost);

  const hi = document.createElementNS(ns, "rect");
  hi.setAttribute("x", 0); hi.setAttribute("width", svgW);
  hi.setAttribute("fill", "#ffffff"); hi.setAttribute("opacity", "0.07");
  hi.setAttribute("pointer-events", "none"); hi.setAttribute("height", 0);
  group.appendChild(hi);

  let targetLevel = null;

  function onMove(e) {
    // Convert screen coords to SVG user space, then to zoom-group content space
    const svgX = (e.clientX - svgRect.left) * scaleX;
    const svgY = (e.clientY - svgRect.top)  * scaleY;
    const contentX = (svgX - otZoomState.x) / otZoomState.k;
    const contentY = (svgY - otZoomState.y) / otZoomState.k;
    ghost.setAttribute("cx", contentX); ghost.setAttribute("cy", contentY);
    targetLevel = null;
    for (const [lvlStr, y] of Object.entries(otLaneY)) {
      const lvl = parseFloat(lvlStr);
      const h   = otLaneH[lvl] ?? 76;
      if (contentY >= y && contentY < y + h) {
        targetLevel = lvl;
        hi.setAttribute("y", y); hi.setAttribute("height", h);
        return;
      }
    }
    hi.setAttribute("height", 0);
  }

  function onUp() {
    document.removeEventListener("mousemove", onMove);
    document.removeEventListener("mouseup",   onUp);
    if (group.contains(ghost)) group.removeChild(ghost);
    if (group.contains(hi)) group.removeChild(hi);
    const currentLvl = otOverrides[node.id] ?? node.purdue_level ?? purdueLevel(node);
    if (targetLevel !== null && targetLevel !== currentLvl) {
      otOverrides[node.id] = targetLevel;
      renderOTMap(graphData);
    }
  }

  document.addEventListener("mousemove", onMove);
  document.addEventListener("mouseup",   onUp);
}

/* ── OT Map risk annotation panel ───────────────────────────────────────── */
function showOTRiskPanel(node, nodePos, svgEl) {
  const panel    = document.getElementById("ot-risk-panel");
  const existing = otRiskLabels[node.id] || { label: "", note: "" };
  document.getElementById("ot-rp-label").textContent = node.hostname || node.ip;
  document.getElementById("ot-rp-note").value = existing.note || "";

  const btns = document.getElementById("ot-rp-btns");
  btns.innerHTML = Object.entries(OT_RISK_COLORS).map(([lvl, col]) =>
    `<button class="ot-risk-btn${existing.label === lvl ? " active" : ""}"
      data-level="${lvl}" style="border-color:${col};color:${col}">${lvl}</button>`
  ).join("") +
  `<button class="ot-risk-btn" data-level="" style="border-color:#555;color:#666">✕ Clear</button>`;

  btns.querySelectorAll(".ot-risk-btn").forEach(btn => {
    btn.addEventListener("click", () => {
      const lbl  = btn.dataset.level;
      const note = document.getElementById("ot-rp-note").value.trim();
      if (!lbl) { delete otRiskLabels[node.id]; }
      else      { otRiskLabels[node.id] = { label: lbl, note }; }
      panel.classList.add("hidden");
      renderOTMap(graphData);
    });
  });

  // Position near the clicked node, clamped to viewport
  if (nodePos && svgEl) {
    const svgRect = svgEl.getBoundingClientRect();
    const svgW = parseFloat(svgEl.getAttribute("width")) || svgRect.width;
    const svgH = parseFloat(svgEl.getAttribute("height")) || svgRect.height;
    const scaleX = svgRect.width / svgW;
    const scaleY = svgRect.height / svgH;
    // Convert content coords → screen coords accounting for zoom
    const screenX = (nodePos.x * otZoomState.k + otZoomState.x) * scaleX + svgRect.left;
    const screenY = (nodePos.y * otZoomState.k + otZoomState.y) * scaleY + svgRect.top;
    const container = document.getElementById("ot-map-view").getBoundingClientRect();
    const panelW = 220, panelH = 160;
    let left = screenX - container.left + 20;
    let top  = screenY - container.top  - panelH / 2;
    // Clamp to container bounds
    left = Math.max(8, Math.min(container.width - panelW - 8, left));
    top  = Math.max(8, Math.min(container.height - panelH - 8, top));
    panel.style.left  = left + "px";
    panel.style.top   = top  + "px";
    panel.style.right = "auto";
  } else {
    panel.style.top   = "80px";
    panel.style.right = "12px";
    panel.style.left  = "auto";
  }
  panel.classList.remove("hidden");
}

/* ── OT Map export (PNG + JSON) ──────────────────────────────────────────── */
function exportOTMapPng() {
  if (!graphData) return;
  const svgEl = document.getElementById("ot-map-svg");
  const W = parseFloat(svgEl.getAttribute("width"))  || 900;
  const H = parseFloat(svgEl.getAttribute("height")) || 600;
  const svgStr = new XMLSerializer().serializeToString(svgEl);
  const url = URL.createObjectURL(new Blob([svgStr], { type: "image/svg+xml;charset=utf-8" }));
  const img = new Image();
  img.onload = () => {
    const canvas = document.createElement("canvas");
    canvas.width = W; canvas.height = H;
    const ctx = canvas.getContext("2d");
    ctx.fillStyle = "#0d1117";
    ctx.fillRect(0, 0, W, H);
    ctx.drawImage(img, 0, 0, W, H);
    URL.revokeObjectURL(url);
    const a = document.createElement("a");
    a.download = `ot-map-risk-${new Date().toISOString().slice(0, 10)}.png`;
    a.href = canvas.toDataURL("image/png");
    a.click();
  };
  img.src = url;
}

function exportOTMapJson() {
  if (!graphData) return;
  const effectiveNodes = [
    ...graphData.nodes.filter(n => !otRemovedIds.has(n.id)),
    ...otAddedNodes,
  ];
  const nodeLvl = {};
  effectiveNodes.forEach(n => {
    nodeLvl[n.id] = (otOverrides[n.id] !== undefined)
      ? otOverrides[n.id]
      : (n.purdue_level !== undefined ? n.purdue_level : purdueLevel(n));
  });
  const payload = {
    exported_at: new Date().toISOString(),
    edit_session: {
      level_overrides: Object.keys(otOverrides).length,
      risk_labels:     Object.keys(otRiskLabels).length,
      added_nodes:     otAddedNodes.length,
      removed_nodes:   otRemovedIds.size,
    },
    nodes: effectiveNodes.map(n => ({
      ip: n.ip, hostname: n.hostname || null,
      host_type: n.host_type,
      purdue_level: nodeLvl[n.id],
      purdue_level_original: n.purdue_level ?? purdueLevel(n),
      purdue_level_overridden: otOverrides[n.id] !== undefined,
      risk_label: otRiskLabels[n.id]?.label || null,
      risk_note:  otRiskLabels[n.id]?.note  || null,
      protocols:  n.protocols,
      mac: n.mac, mac_vendor: n.mac_vendor,
      is_private: n.is_private,
      added_manually: n.added_manually || false,
    })),
    edges: graphData.edges
      .filter(e => !otRemovedIds.has(e.source) && !otRemovedIds.has(e.target))
      .map(e => ({ source: e.source, target: e.target,
        protocols: e.protocols, packet_count: e.packet_count, bytes: e.bytes })),
  };
  const ts   = new Date().toISOString().replace(/[:.]/g, "-").slice(0, 19);
  const blob = new Blob([JSON.stringify(payload, null, 2)], { type: "application/json" });
  const url  = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url; a.download = `ot-map-${ts}.json`; a.click();
  URL.revokeObjectURL(url);
}

/* ── DNS Map View ────────────────────────────────────────────────────────── */
function renderDnsMap() {
  if (!graphData) return;
  const hostsEl = document.getElementById("dns-hosts");
  hostsEl.innerHTML = "";

  const dnsHosts = graphData.nodes.filter(n => n.dns_queries && n.dns_queries.length > 0);

  if (dnsHosts.length === 0) {
    hostsEl.innerHTML = `<div style="padding:12px;font-size:12px;color:var(--text2)">No DNS queries found in this capture.</div>`;
    return;
  }

  dnsHosts.forEach(n => {
    const row = document.createElement("div");
    row.className = "dns-host-row";
    row.innerHTML = `
      <span style="font-family:var(--font-mono);font-size:11px">${n.ip}</span>
      <span class="dns-count">${n.dns_queries.length}</span>
    `;
    row.addEventListener("click", () => {
      document.querySelectorAll(".dns-host-row").forEach(r => r.classList.remove("selected"));
      row.classList.add("selected");
      showDnsQueries(n);
    });
    hostsEl.appendChild(row);
  });
}

function showDnsQueries(node) {
  const title = document.getElementById("dns-query-title");
  const list = document.getElementById("dns-queries-list");
  title.textContent = `DNS queries from ${node.ip}`;
  list.innerHTML = "";

  node.dns_queries.forEach(q => {
    const div = document.createElement("div");
    div.className = "dns-query-entry";
    // Try to find resolved IPs from dns_names of other nodes
    const resolvedIps = [];
    if (graphData) {
      graphData.nodes.forEach(n => {
        if (n.dns_names && n.dns_names.some(name => name === q || name.endsWith("." + q))) {
          resolvedIps.push(n.ip);
        }
      });
    }
    div.innerHTML = `
      <div class="dns-q-name">${escHtml(q)}</div>
      ${resolvedIps.length ? `<div class="dns-resolved">→ ${resolvedIps.join(", ")}</div>` : ""}
    `;
    list.appendChild(div);
  });
}

/* ── Export ──────────────────────────────────────────────────────────────── */
document.getElementById("export-btn").addEventListener("click", (e) => {
  e.stopPropagation();
  const menu = document.getElementById("export-menu");
  menu.classList.toggle("hidden");
});

document.addEventListener("click", () => {
  document.getElementById("export-menu").classList.add("hidden");
});

document.getElementById("exp-png").addEventListener("click", () => {
  exportPng();
  document.getElementById("export-menu").classList.add("hidden");
});

/* ── OT Map toolbar wiring ───────────────────────────────────────────────── */
document.getElementById("ot-edit-btn").addEventListener("click", () => {
  otEditMode = !otEditMode;
  const btn = document.getElementById("ot-edit-btn");
  btn.textContent = otEditMode ? "✓ Editing" : "✎ Edit";
  btn.classList.toggle("active", otEditMode);
  document.getElementById("ot-add-btn").classList.toggle("hidden", !otEditMode);
  document.getElementById("ot-map-view").classList.toggle("ot-edit-active", otEditMode);
  document.getElementById("ot-risk-panel").classList.add("hidden");
  document.getElementById("ot-edit-hint").classList.toggle("hidden", !otEditMode);
  if (graphData) renderOTMap(graphData);
});

document.getElementById("ot-hint-close-btn").addEventListener("click", () => {
  document.getElementById("ot-edit-hint").classList.add("hidden");
});

document.getElementById("ot-add-btn").addEventListener("click", () =>
  document.getElementById("ot-add-modal").classList.remove("hidden"));

document.getElementById("ot-am-close").addEventListener("click", () =>
  document.getElementById("ot-add-modal").classList.add("hidden"));

document.getElementById("ot-am-confirm").addEventListener("click", () => {
  const ip = document.getElementById("ot-am-ip").value.trim();
  if (!ip) { document.getElementById("ot-am-ip").focus(); return; }
  const lvl = parseFloat(document.getElementById("ot-am-level").value);
  // Prevent duplicate IDs
  if (otAddedNodes.some(a => a.id === ip) || (graphData && graphData.nodes.some(n => n.id === ip))) {
    const errEl = document.getElementById("ot-am-error");
    errEl.textContent = `A device with IP ${ip} already exists.`;
    setTimeout(() => { errEl.textContent = ""; }, 3000);
    return;
  }
  otAddedNodes.push({
    id: ip, ip,
    hostname:  document.getElementById("ot-am-host").value.trim() || null,
    host_type: document.getElementById("ot-am-type").value || "Unknown",
    purdue_level: isNaN(lvl) ? -1 : lvl,
    protocols: [], services: [], open_ports: [], dns_queries: [], dns_names: [],
    mac: null, mac_vendor: null, os_hint: null, is_private: true,
    flags: [], geo: null, ot_role: "unknown",
    modbus_unit_ids: [], dnp3_addresses: [], added_manually: true,
  });
  ["ot-am-ip", "ot-am-host"].forEach(id => document.getElementById(id).value = "");
  document.getElementById("ot-add-modal").classList.add("hidden");
  renderOTMap(graphData);
});

document.getElementById("ot-rp-close").addEventListener("click", () =>
  document.getElementById("ot-risk-panel").classList.add("hidden"));

// Zoom button handlers
document.getElementById("ot-zoom-in-btn").addEventListener("click", () => {
  if (!otZoom) return;
  d3.select("#ot-map-svg").transition().duration(250).call(otZoom.scaleBy, 1.5);
});
document.getElementById("ot-zoom-out-btn").addEventListener("click", () => {
  if (!otZoom) return;
  d3.select("#ot-map-svg").transition().duration(250).call(otZoom.scaleBy, 1 / 1.5);
});
document.getElementById("ot-zoom-fit-btn").addEventListener("click", () => {
  if (!otZoom) return;
  otZoomState = d3.zoomIdentity;
  d3.select("#ot-map-svg").transition().duration(300).call(otZoom.transform, d3.zoomIdentity);
});

// "Show all" filter toggle — wired from a data attribute on the OT toolbar button if present
(function() {
  const filterBtn = document.getElementById("ot-filter-btn");
  if (!filterBtn) return;
  filterBtn.addEventListener("click", () => {
    otFilterAll = !otFilterAll;
    filterBtn.textContent = otFilterAll ? "Filtered: off" : "Respect filters";
    filterBtn.classList.toggle("active", otFilterAll);
    if (graphData) renderOTMap(graphData);
  });
})();

// ResizeObserver: re-render OT map when #ot-map-view size changes
let _otResizeTimer = null;
new ResizeObserver(() => {
  if (currentView !== "ot") return;
  clearTimeout(_otResizeTimer);
  _otResizeTimer = setTimeout(() => { if (graphData) renderOTMap(graphData); }, 150);
}).observe(document.getElementById("ot-map-view"));

document.getElementById("ot-export-png-btn").addEventListener("click", exportOTMapPng);
document.getElementById("ot-export-json-btn").addEventListener("click", exportOTMapJson);
document.getElementById("exp-csv").addEventListener("click", () => {
  exportCsv();
  document.getElementById("export-menu").classList.add("hidden");
});
document.getElementById("exp-anomalies").addEventListener("click", () => {
  exportAnomalies();
  document.getElementById("export-menu").classList.add("hidden");
});

function exportPng() {
  const svgEl = document.getElementById("graph-svg");
  const serializer = new XMLSerializer();
  const svgStr = serializer.serializeToString(svgEl);
  const svgBlob = new Blob([svgStr], { type: "image/svg+xml;charset=utf-8" });
  const url = URL.createObjectURL(svgBlob);
  const img = new Image();
  img.onload = function() {
    const canvas = document.createElement("canvas");
    canvas.width = svgEl.clientWidth || 1200;
    canvas.height = svgEl.clientHeight || 800;
    const ctx = canvas.getContext("2d");
    ctx.fillStyle = "#0d1117";
    ctx.fillRect(0, 0, canvas.width, canvas.height);
    ctx.drawImage(img, 0, 0);
    URL.revokeObjectURL(url);
    const a = document.createElement("a");
    a.download = "network-graph.png";
    a.href = canvas.toDataURL("image/png");
    a.click();
  };
  img.src = url;
}

function exportCsv() {
  if (!graphData) return;
  const rows = [["Source IP", "Destination IP", "Protocols", "Packets", "Bytes", "Ports", "Duration"]];
  graphData.edges.forEach(e => {
    const duration = (e.first_seen != null && e.last_seen != null)
      ? (e.last_seen - e.first_seen).toFixed(3)
      : "";
    rows.push([
      e.source,
      e.target,
      e.protocols.join(";"),
      e.packet_count,
      e.bytes,
      e.ports.join(";"),
      duration,
    ]);
  });
  downloadCsv(rows, "connections.csv");
}

function exportAnomalies() {
  if (!graphData || !(graphData.anomalies || []).length) {
    alert("No anomalies to export.");
    return;
  }
  const rows = [["Type", "Severity", "Source", "Destination", "Description"]];
  graphData.anomalies.forEach(a => {
    rows.push([a.type, a.severity, a.src || "", a.dst || "", a.description]);
  });
  downloadCsv(rows, "anomalies.csv");
}

function downloadCsv(rows, filename) {
  const csv = rows.map(r => r.map(v => `"${String(v).replace(/"/g, '""')}"`).join(",")).join("\n");
  const blob = new Blob([csv], { type: "text/csv;charset=utf-8;" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  a.click();
  URL.revokeObjectURL(url);
}

/* ── Sessions ────────────────────────────────────────────────────────────── */
document.getElementById("save-session-btn").addEventListener("click", () => {
  if (!graphData) { alert("No data loaded."); return; }
  const sessionData = {
    nodes: graphData.nodes,
    edges: graphData.edges,
    stats: graphData.stats,
    anomalies: graphData.anomalies || [],
    packets: graphData.packets || {},
  };
  const ts = new Date().toISOString().replace(/[:.]/g, "-").slice(0, 19);
  const blob = new Blob([JSON.stringify(sessionData)], { type: "application/json" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = `session-${ts}.json`;
  a.click();
  URL.revokeObjectURL(url);
});

document.getElementById("load-session-btn").addEventListener("click", () => {
  document.getElementById("session-file-input").click();
});

document.getElementById("session-file-input").addEventListener("change", (e) => {
  const file = e.target.files[0];
  if (!file) return;
  const reader = new FileReader();
  reader.onload = (ev) => {
    try {
      const data = JSON.parse(ev.target.result);
      if (!data.nodes || !data.edges) throw new Error("Invalid session file");
      loadGraph(data);
    } catch (err) {
      alert("Failed to load session: " + err.message);
    }
  };
  reader.readAsText(file);
  e.target.value = "";
});

/* ── Node annotations ────────────────────────────────────────────────────── */
function getAnnotation(ip) {
  return localStorage.getItem("ann:" + ip) || "";
}

function saveAnnotation(ip, text) {
  if (text) {
    localStorage.setItem("ann:" + ip, text);
  } else {
    localStorage.removeItem("ann:" + ip);
  }
}

function applyAnnotations() {
  if (!graphData) return;
  nodesGroup.selectAll(".node").each(function(d) {
    const note = getAnnotation(d.ip);
    const g = d3.select(this);
    g.selectAll(".node-note-icon").remove();
    if (note) {
      const r = 6 + Math.log1p(d.packet_count / Math.max(...graphData.nodes.map(n => n.packet_count), 1) * 200) * 3;
      g.append("text")
        .attr("class", "node-note-icon")
        .attr("dy", -(r + 4))
        .attr("font-size", "10px")
        .text("✎");
    }
  });
}

function updateNoteIcon(ip, hasNote) {
  if (!graphData) return;
  nodesGroup.selectAll(".node").each(function(d) {
    if (d.ip !== ip) return;
    const g = d3.select(this);
    g.selectAll(".node-note-icon").remove();
    if (hasNote) {
      const r = 6 + Math.log1p(d.packet_count / Math.max(...graphData.nodes.map(n => n.packet_count), 1) * 200) * 3;
      g.append("text")
        .attr("class", "node-note-icon")
        .attr("dy", -(r + 4))
        .attr("font-size", "10px")
        .text("✎");
    }
  });
}

/* ── Context menu ────────────────────────────────────────────────────────── */
let ctxTarget = null;

function showCtxMenu(event, d) {
  ctxTarget = d;
  ctxMenu.style.left = event.clientX + "px";
  ctxMenu.style.top  = event.clientY + "px";
  ctxMenu.classList.remove("hidden");
}

document.getElementById("ctx-add-note").addEventListener("click", () => {
  ctxMenu.classList.add("hidden");
  if (!ctxTarget) return;
  const existing = getAnnotation(ctxTarget.ip);
  const input = prompt("Add a note for " + ctxTarget.ip + ":", existing || "");
  if (input !== null) {
    saveAnnotation(ctxTarget.ip, input);
    updateNoteIcon(ctxTarget.ip, !!input);
    if (selectedNode && selectedNode.ip === ctxTarget.ip) {
      showDetailPanel(ctxTarget);
    }
  }
  ctxTarget = null;
});

document.addEventListener("click", () => {
  ctxMenu.classList.add("hidden");
});

/* ── Timeline ────────────────────────────────────────────────────────────── */
function buildTimeline(data) {
  const tlBar = document.getElementById("timeline-bar");

  // Collect all packet timestamps from packetData
  const allTimes = [];
  for (const pkts of Object.values(data.packets || {})) {
    pkts.forEach(p => { if (p.time != null) allTimes.push(p.time); });
  }

  if (allTimes.length < 2) {
    tlBar.classList.add("hidden");
    return;
  }

  tlBar.classList.remove("hidden");

  const minT = Math.min(...allTimes);
  const maxT = Math.max(...allTimes);
  const span = maxT - minT;

  // Build minimap
  const minimap = document.getElementById("tl-minimap");
  minimap.innerHTML = "";
  const BINS = 60;
  const bins = new Array(BINS).fill(0);
  allTimes.forEach(t => {
    const idx = Math.min(Math.floor(((t - minT) / span) * BINS), BINS - 1);
    bins[idx]++;
  });
  const maxBin = Math.max(...bins, 1);
  bins.forEach(count => {
    const bar = document.createElement("div");
    bar.className = "tl-bar";
    bar.style.height = Math.max(2, (count / maxBin) * 20) + "px";
    minimap.appendChild(bar);
  });

  const slider = document.getElementById("tl-slider");
  const timeLabel = document.getElementById("tl-time-label");

  slider.value = 100;
  timeLabel.textContent = "All time";
  tlWindowPct = 100;

  let _tlRafPending = false;
  slider.oninput = () => {
    if (_tlRafPending) return;
    _tlRafPending = true;
    requestAnimationFrame(() => {
      _tlRafPending = false;
      const pct = parseInt(slider.value) / 100;
      tlWindowPct = parseInt(slider.value);
      if (pct >= 1.0) {
        timeLabel.textContent = "All time";
        applyTimelineFilter(null, null);
      } else {
        const windowSize = span * 0.15; // 15% window
        const center = minT + pct * span;
        const tStart = center - windowSize / 2;
        const tEnd   = center + windowSize / 2;
        timeLabel.textContent = center.toFixed(2) + "s";
        applyTimelineFilter(tStart, tEnd);
      }
    });
  };
}

function applyTimelineFilter(tStart, tEnd) {
  if (!graphData) return;

  if (tStart === null) {
    // Show all
    nodesGroup.selectAll(".node").classed("faded", false);
    linksGroup.selectAll(".link").classed("faded", false);
    applyFilters();
    return;
  }

  // Collect IPs visible in time window
  const visibleIps = new Set();
  for (const [key, pkts] of Object.entries(packetData)) {
    const inWindow = pkts.some(p => p.time >= tStart && p.time <= tEnd);
    if (inWindow) {
      const [a, b] = key.split("|");
      visibleIps.add(a);
      visibleIps.add(b);
    }
  }

  nodesGroup.selectAll(".node").each(function(d) {
    d3.select(this).classed("faded", !visibleIps.has(d.ip));
  });

  linksGroup.selectAll(".link").each(function(d) {
    const sid = d.source.id || d.source;
    const tid = d.target.id || d.target;
    d3.select(this).classed("faded", !visibleIps.has(sid) || !visibleIps.has(tid));
  });
}

// Play button
document.getElementById("tl-play-btn").addEventListener("click", () => {
  const btn = document.getElementById("tl-play-btn");
  const slider = document.getElementById("tl-slider");

  if (tlPlaying) {
    clearInterval(tlTimer);
    tlPlaying = false;
    btn.textContent = "▶";
  } else {
    tlPlaying = true;
    btn.textContent = "⏸";
    if (parseInt(slider.value) >= 100) slider.value = 0;
    tlTimer = setInterval(() => {
      const cur = parseInt(slider.value);
      if (cur >= 100) {
        clearInterval(tlTimer);
        tlPlaying = false;
        btn.textContent = "▶";
        slider.dispatchEvent(new Event("input"));
        return;
      }
      slider.value = cur + 1;
      slider.dispatchEvent(new Event("input"));
    }, 80);
  }
});
