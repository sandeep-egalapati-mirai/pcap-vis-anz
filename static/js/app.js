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

/* ── State ───────────────────────────────────────────────────────────────── */
let graphData    = null;
let simulation   = null;
let selectedNode = null;
let activeProtos = new Set();
let activeTypes  = new Set();
let searchTerm   = "";

/* ── DOM refs ────────────────────────────────────────────────────────────── */
const svg           = d3.select("#graph-svg");
const tooltip       = document.getElementById("tooltip");
const detailPanel   = document.getElementById("detail-panel");
const modalOverlay  = document.getElementById("modal-overlay");
const loadingOverlay= document.getElementById("loading-overlay");
const fileInput     = document.getElementById("file-input");
const dropZone      = document.getElementById("drop-zone");
const modalError    = document.getElementById("modal-error");
const truncBanner   = document.getElementById("trunc-banner");
const searchBox     = document.getElementById("search-box");

/* ── SVG setup ───────────────────────────────────────────────────────────── */
const zoomGroup = svg.append("g").attr("id", "zoom-group");
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
  if (fileInput.files[0]) uploadFile(fileInput.files[0]);
});

dropZone.addEventListener("dragover", (e) => { e.preventDefault(); dropZone.classList.add("drag-over"); });
dropZone.addEventListener("dragleave", () => dropZone.classList.remove("drag-over"));
dropZone.addEventListener("drop", (e) => {
  e.preventDefault();
  dropZone.classList.remove("drag-over");
  const file = e.dataTransfer.files[0];
  if (file) uploadFile(file);
});

// Close modal on overlay click
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

async function uploadFile(file) {
  const allowed = ["pcap","pcapng","cap"];
  const ext = file.name.split(".").pop().toLowerCase();
  if (!allowed.includes(ext)) {
    modalError.textContent = "Unsupported file type. Use .pcap, .pcapng, or .cap";
    return;
  }
  modalError.textContent = "";
  closeModal();
  loadingOverlay.classList.remove("hidden");

  const form = new FormData();
  form.append("file", file);

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
  renderGraph(data);
}

function buildFilters(data) {
  buildFilterList("proto-filters", data.stats.protocols, activeProtos, PROTO_COLORS, "proto");
  buildFilterList("type-filters",  data.stats.host_types, activeTypes,  HOST_COLORS,  "type");
}

function buildFilterList(containerId, items, activeSet, colorMap, kind) {
  const container = document.getElementById(containerId);
  container.innerHTML = "";

  // Count occurrences
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
    div.innerHTML = `
      <input type="checkbox" id="f-${kind}-${CSS.escape(item)}" checked>
      <div class="dot" style="background:${color}"></div>
      <label for="f-${kind}-${CSS.escape(item)}">${item}</label>
      <span class="count">${counts[item] || 0}</span>
    `;
    const cb = div.querySelector("input");
    cb.addEventListener("change", () => {
      if (cb.checked) activeSet.add(item);
      else activeSet.delete(item);
      applyFilters();
    });
    container.appendChild(div);
  });
}

function applyFilters() {
  if (!graphData) return;

  // Determine visible nodes, collect their IDs
  const visibleNodeIds = new Set();
  nodesGroup.selectAll(".node").each(function(d) {
    const visible = activeTypes.has(d.host_type) &&
      (!searchTerm || d.ip.includes(searchTerm) ||
       (d.hostname && d.hostname.toLowerCase().includes(searchTerm)));
    d3.select(this).classed("faded", !visible);
    if (visible) visibleNodeIds.add(d.id);
  });

  // Hide edges whose protocol is filtered out or either endpoint is hidden
  linksGroup.selectAll(".link").each(function(d) {
    const protoOk = d.protocols.some(p => activeProtos.has(p));
    const sid = d.source.id || d.source;
    const tid = d.target.id || d.target;
    const visible = protoOk && visibleNodeIds.has(sid) && visibleNodeIds.has(tid);
    d3.select(this).classed("faded", !visible);
  });
}

/* ── D3 force graph ──────────────────────────────────────────────────────── */
function renderGraph(data) {
  // Clear previous
  linksGroup.selectAll("*").remove();
  nodesGroup.selectAll("*").remove();
  if (simulation) simulation.stop();

  // Build node lookup map (attach to data for filter access)
  data._nodeMap = {};
  data.nodes.forEach(n => { data._nodeMap[n.id] = n; n._visible = true; });

  // Deep-copy nodes/links for simulation (d3 mutates them)
  const nodes = data.nodes.map(d => ({ ...d }));
  const nodeById = {};
  nodes.forEach(n => nodeById[n.id] = n);

  const links = data.edges
    .filter(e => nodeById[e.source] && nodeById[e.target])
    .map(e => ({
      ...e,
      source: e.source,
      target: e.target,
    }));

  // Node radius based on total traffic
  const maxPkt = Math.max(...nodes.map(n => n.packet_count), 1);
  function nodeRadius(d) {
    return 6 + Math.log1p(d.packet_count / maxPkt * 200) * 3;
  }

  // Edge width based on packet count
  const maxEdgePkt = Math.max(...links.map(e => e.packet_count), 1);
  function edgeWidth(d) {
    return 1 + Math.log1p(d.packet_count / maxEdgePkt * 50) * 1.2;
  }

  // ── Links ──
  const linkSel = linksGroup.selectAll(".link")
    .data(links)
    .join("line")
    .attr("class", "link")
    .attr("stroke", d => protoColor(d.protocols))
    .attr("stroke-width", d => edgeWidth(d))
    .on("mouseenter", (event, d) => {
      showTooltipEdge(event, d);
    })
    .on("mousemove", (event) => {
      positionTooltip(event);
    })
    .on("mouseleave", () => hideTooltip());

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
      .on("drag", (event, d) => {
        d.fx = event.x; d.fy = event.y;
      })
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
    });

  // circle
  nodeSel.append("circle")
    .attr("r", d => nodeRadius(d))
    .attr("fill", d => hostColor(d.host_type))
    .attr("fill-opacity", 0.85)
    .attr("stroke", d => d3.color(hostColor(d.host_type)).brighter(0.5));

  // icon character
  nodeSel.append("text")
    .attr("dy", "0.35em")
    .attr("font-size", d => Math.min(nodeRadius(d) - 1, 11) + "px")
    .text(d => hostIcon(d.host_type));

  // IP label below node
  nodeSel.append("text")
    .attr("dy", d => nodeRadius(d) + 11)
    .attr("font-size", "9px")
    .attr("fill", "#8b949e")
    .text(d => d.hostname || d.ip);

  // Click on background → deselect
  svg.on("click", () => {
    selectedNode = null;
    unhighlightAll(linkSel, nodeSel);
    nodeSel.classed("selected", false);
    detailPanel.classList.remove("open");
  });

  // ── Simulation ──
  simulation = d3.forceSimulation(nodes)
    .force("link", d3.forceLink(links).id(d => d.id).distance(90).strength(0.4))
    .force("charge", d3.forceManyBody().strength(-200).distanceMax(400))
    .force("center", d3.forceCenter(
      svg.node().clientWidth / 2,
      svg.node().clientHeight / 2
    ))
    .force("collide", d3.forceCollide().radius(d => nodeRadius(d) + 12))
    .on("tick", () => {
      linkSel
        .attr("x1", d => d.source.x)
        .attr("y1", d => d.source.y)
        .attr("x2", d => d.target.x)
        .attr("y2", d => d.target.y);
      nodeSel.attr("transform", d => `translate(${d.x},${d.y})`);
    });

  // Zoom to fit after settling
  simulation.on("end", () => zoomFit());
  setTimeout(() => zoomFit(), 2500);
}

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
  tooltip.innerHTML = `
    <div class="tip-ip">${d.ip}</div>
    ${d.hostname ? `<div class="tip-type">${d.hostname}</div>` : ""}
    <div class="tip-type">${d.host_type}${d.os_hint ? " · " + d.os_hint : ""}</div>
    <div class="tip-proto">
      ${d.protocols.slice(0, 6).map(p =>
        `<span style="color:${PROTO_COLORS[p] || '#aaa'}">${p}</span>`
      ).join(" · ")}
    </div>
    <div class="tip-type" style="margin-top:4px">
      ${fmtNum(d.packet_count)} pkts · ${fmtBytes(d.bytes_sent + d.bytes_recv)}
    </div>
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
  if (d.os_hint)     rows.push(row("OS guess",   mono(d.os_hint)));
  if (d.mac)         rows.push(row("MAC", mono(d.mac) + (d.mac_vendor ? ` <span style="color:var(--text2)">(${d.mac_vendor})</span>` : "")));
  rows.push(row("Traffic",
    `<span style="color:#3fb950">↑ ${fmtBytes(d.bytes_sent)}</span>  ` +
    `<span style="color:#58a6ff">↓ ${fmtBytes(d.bytes_recv)}</span>`));
  rows.push(row("Packets", mono(fmtNum(d.packet_count))));
  rows.push(row("Private IP", mono(d.is_private ? "Yes" : "No")));

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
    d.dns_names.forEach(n => rows.push(`<div class="d-val" style="font-family:var(--font-mono);font-size:11px;margin-bottom:3px">${n}</div>`));
  }

  if (d.dns_queries.length) {
    rows.push(sectionTitle("DNS queries sent"));
    d.dns_queries.forEach(q => rows.push(`<div class="d-val" style="font-family:var(--font-mono);font-size:11px;margin-bottom:3px;color:var(--text2)">${q}</div>`));
  }

  body.innerHTML = rows.join("");
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
});

/* ── Search ──────────────────────────────────────────────────────────────── */
searchBox.addEventListener("input", () => {
  searchTerm = searchBox.value.trim().toLowerCase();
  applyFilters();

  // Auto-select matching node
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
    div.innerHTML = `<div class="legend-dot" style="background:${hostColor(ht)}"></div><span>${ht}</span>`;
    hostLegend.appendChild(div);
  });
}

/* ── Host icon ───────────────────────────────────────────────────────────── */
function hostIcon(type) {
  const icons = {
    "Web Server":      "W",
    "DNS Server":      "D",
    "DHCP Server":     "H",
    "SSH Server":      "S",
    "Telnet Server":   "T",
    "FTP Server":      "F",
    "Mail Server":     "M",
    "Database Server": "B",
    "Cache Server":    "C",
    "Windows Host":    "W",
    "Linux Host":      "L",
    "Linux Server":    "L",
    "Network Device":  "N",
    "Router":          "R",
    "VPN Gateway":     "V",
    "Container Host":  "K",
    "Internet Host":   "I",
    "Broadcast":       "•",
    "Multicast":       "•",
  };
  return icons[type] || "?";
}


/* ── On page load: show upload modal ─────────────────────────────────────── */
window.addEventListener("load", () => {
  loadingOverlay.classList.add("hidden");
  modalOverlay.classList.remove("hidden");
});
