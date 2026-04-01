const PRODUCER = "ossiqn";
const TOOL     = "HoneyTrap Network";
const VERSION  = "1.0.0";

const state = {
    currentPage:      1,
    pageSize:         50,
    trapFilter:       null,
    severityFilter:   null,
    selectedAttack:   null,
    attacks:          [],
    activeTab:        "attacks"
};

async function refreshAttacks() {
    try {
        const params = new URLSearchParams({
            limit:  state.pageSize,
            offset: (state.currentPage - 1) * state.pageSize
        });

        if (state.trapFilter)     params.append("trap_type", state.trapFilter);
        if (state.severityFilter) params.append("severity",  state.severityFilter);

        const res  = await fetch(`/api/attacks?${params}`);
        const data = await res.json();

        state.attacks = data.attacks || [];
        renderAttacks(state.attacks);

        document.getElementById("loadingState").style.display = "none";
        document.getElementById("liveCount").textContent = `${state.attacks.length} attacks`;

    } catch (e) {
        termLog("ERR", `[${PRODUCER}] Failed to load attacks: ${e.message}`);
    }
}

async function refreshStats() {
    try {
        const res   = await fetch("/api/stats");
        const stats = await res.json();

        document.getElementById("totalAttacks").textContent = stats.total      || 0;
        document.getElementById("uniqueIPs").textContent    = stats.unique_ips || 0;
        document.getElementById("recent24h").textContent    = stats.recent_24h || 0;
        document.getElementById("iocCount").textContent     = stats.ioc_count  || 0;

        const sev = stats.severity_counts || {};
        document.getElementById("criticalCount").textContent = sev.critical || 0;
        document.getElementById("highCount").textContent     = sev.high     || 0;

        document.getElementById("sc-critical").textContent  = sev.critical || 0;
        document.getElementById("sc-high").textContent      = sev.high     || 0;
        document.getElementById("sc-medium").textContent    = sev.medium   || 0;
        document.getElementById("sc-low").textContent       = sev.low      || 0;
        document.getElementById("sc-all").textContent       = stats.total  || 0;

    } catch(e) {
        console.error(`[${PRODUCER}] Stats refresh failed:`, e);
    }
}

function renderAttacks(attacks) {
    const list  = document.getElementById("attacksList");
    const empty = document.getElementById("emptyState");

    list.innerHTML = "";

    if (!attacks || attacks.length === 0) {
        empty.style.display = "flex";
        return;
    }

    empty.style.display = "none";
    attacks.forEach(a => list.appendChild(createAttackCard(a)));

    document.getElementById("prevBtn").disabled = state.currentPage === 1;
    document.getElementById("nextBtn").disabled = attacks.length < state.pageSize;
    document.getElementById("pageInfo").textContent = `Page ${state.currentPage}`;
}

function createAttackCard(attack) {
    const card     = document.createElement("div");
    card.className = `attack-card ${attack.severity || "low"}`;
    card.dataset.id = attack.id;

    const ts   = new Date(attack.timestamp);
    const time = ts.toLocaleTimeString("en-US", {hour12:false, hour:"2-digit", minute:"2-digit", second:"2-digit"});
    const date = ts.toLocaleDateString("en-US", {month:"2-digit", day:"2-digit"});

    const flagMap = {
        "United States":"🇺🇸","China":"🇨🇳","Russia":"🇷🇺","Germany":"🇩🇪",
        "United Kingdom":"🇬🇧","France":"🇫🇷","Netherlands":"🇳🇱","Turkey":"🇹🇷",
        "Brazil":"🇧🇷","India":"🇮🇳","Japan":"🇯🇵","South Korea":"🇰🇷",
        "Iran":"🇮🇷","Ukraine":"🇺🇦","Romania":"🇷🇴","Unknown":"🌍"
    };

    const flag    = flagMap[attack.country] || "🌍";
    const payload = attack.payload ? attack.payload.substring(0, 80) : "";

    card.innerHTML = `
        <div class="card-header">
            <span class="card-sev ${attack.severity || 'low'}">${(attack.severity||"low").toUpperCase()}</span>
            <span class="card-title">${escHtml(attack.attack_type?.replace(/_/g," ").toUpperCase() || "UNKNOWN ATTACK")}</span>
            <span class="card-trap">${(attack.trap_type||"unknown").toUpperCase()}</span>
        </div>
        <div class="card-meta">
            <span>${flag} ${escHtml(attack.country||"Unknown")}</span>
            <span>🖥️ ${escHtml(attack.attacker_ip||"")}</span>
            <span>🔥 ${attack.threat_score||0}/100</span>
            <span>🕐 ${date} ${time}</span>
            ${attack.is_vpn ? '<span>🔒 VPN</span>' : ''}
        </div>
        ${payload ? `<div class="card-payload">↳ ${escHtml(payload)}${payload.length >= 80 ? '...' : ''}</div>` : ''}
    `;

    card.addEventListener("click", () => showDetail(attack));
    return card;
}

function showDetail(attack) {
    state.selectedAttack = attack;

    const content  = document.getElementById("detailContent");
    const sevClass = `c-${attack.severity || "low"}`;

    let rawHtml = "";
    if (attack.raw_data) {
        try {
            const raw = typeof attack.raw_data === "string" ? JSON.parse(attack.raw_data) : attack.raw_data;
            rawHtml = `<div class="detail-field"><div class="detail-label">RAW DATA</div><div class="detail-value">${escHtml(JSON.stringify(raw,null,2))}</div></div>`;
        } catch(_) {}
    }

    content.innerHTML = `
        <div class="detail-field"><div class="detail-label">SEVERITY</div><div class="detail-value ${sevClass}">${(attack.severity||"").toUpperCase()}</div></div>
        <div class="detail-field"><div class="detail-label">ATTACK TYPE</div><div class="detail-value">${escHtml(attack.attack_type||"")}</div></div>
        <div class="detail-field"><div class="detail-label">TRAP TYPE</div><div class="detail-value">${escHtml(attack.trap_type||"")}</div></div>
        <div class="detail-field"><div class="detail-label">ATTACKER IP</div><div class="detail-value">${escHtml(attack.attacker_ip||"")}</div></div>
        <div class="detail-field"><div class="detail-label">COUNTRY / CITY</div><div class="detail-value">${escHtml(attack.country||"")} / ${escHtml(attack.city||"")}</div></div>
        <div class="detail-field"><div class="detail-label">ISP / ASN</div><div class="detail-value">${escHtml(attack.isp||"")} / ${escHtml(attack.asn||"")}</div></div>
        <div class="detail-field"><div class="detail-label">THREAT SCORE</div><div class="detail-value">${attack.threat_score||0} / 100</div></div>
        <div class="detail-field"><div class="detail-label">VPN / PROXY</div><div class="detail-value">${attack.is_vpn ? "YES ⚠️" : "NO"}</div></div>
        <div class="detail-field"><div class="detail-label">TIMESTAMP</div><div class="detail-value">${new Date(attack.timestamp).toLocaleString()}</div></div>
        ${attack.username ? `<div class="detail-field"><div class="detail-label">USERNAME</div><div class="detail-value">${escHtml(attack.username)}</div></div>` : ""}
        ${attack.password ? `<div class="detail-field"><div class="detail-label">PASSWORD</div><div class="detail-value">${escHtml(attack.password)}</div></div>` : ""}
        ${attack.endpoint ? `<div class="detail-field"><div class="detail-label">ENDPOINT</div><div class="detail-value">${escHtml(attack.endpoint)}</div></div>` : ""}
        ${attack.user_agent ? `<div class="detail-field"><div class="detail-label">USER AGENT</div><div class="detail-value">${escHtml(attack.user_agent)}</div></div>` : ""}
        ${attack.payload ? `<div class="detail-field"><div class="detail-label">PAYLOAD</div><div class="detail-value">${escHtml(attack.payload.substring(0,500))}</div></div>` : ""}
        ${rawHtml}
        <div class="detail-field" style="padding:8px;border:1px solid rgba(170,68,255,0.2);border-radius:2px;background:rgba(170,68,255,0.03);margin-top:10px;">
            <div class="detail-label" style="color:rgba(170,68,255,0.6)">PRODUCED BY</div>
            <div style="font-size:11px;color:rgba(170,68,255,0.8);letter-spacing:2px">${PRODUCER} · ossiqn.com.tr</div>
        </div>
        <button class="blacklist-btn" onclick="blacklistIP('${escHtml(attack.attacker_ip||"")}')">🚫 BLACKLIST THIS IP</button>
    `;
}

function closeDetail() {
    document.getElementById("detailContent").innerHTML = '<div class="detail-empty">Select an attack to view details</div>';
    state.selectedAttack = null;
}

async function blacklistIP(ip) {
    try {
        const res = await fetch(`/api/blacklist/${ip}`, {
            method: "POST",
            headers: {"Content-Type": "application/json"},
            body: JSON.stringify({reason: "manual_from_dashboard"})
        });
        if (res.ok) {
            termLog("SYS", `[${PRODUCER}] IP blacklisted: ${ip}`);
        }
    } catch(e) {
        termLog("ERR", `[${PRODUCER}] Blacklist failed: ${e.message}`);
    }
}

async function showIOCPanel() {
    switchTab("ioc");
    try {
        const res  = await fetch("/api/ioc");
        const data = await res.json();
        const list = document.getElementById("iocList");
        list.innerHTML = "";

        (data.iocs || []).forEach(ioc => {
            const scoreClass = ioc.threat_score >= 70 ? "s-high" : ioc.threat_score >= 40 ? "s-medium" : "s-low";
            const card       = document.createElement("div");
            card.className   = "ioc-card";
            card.innerHTML   = `
                <span class="ioc-type">${(ioc.ioc_type||"").toUpperCase()}</span>
                <span class="ioc-value">${escHtml(ioc.ioc_value||"")}</span>
                <span class="ioc-score ${scoreClass}">${ioc.threat_score||0}</span>
            `;
            list.appendChild(card);
        });
    } catch(e) {
        termLog("ERR", `[${PRODUCER}] IOC load failed: ${e.message}`);
    }
}

async function showMap() {
    switchTab("map");
    try {
        const res  = await fetch("/api/geo");
        const data = await res.json();
        const mapEl = document.getElementById("mapCoords");
        const points = data.points || [];
        mapEl.textContent = `${points.length} attack origins loaded · ossiqn`;
    } catch(e) {}
}

async function exportIOC() {
    try {
        const res  = await fetch("/api/ioc/export");
        const data = await res.json();
        const blob = new Blob([JSON.stringify(data, null, 2)], {type:"application/json"});
        const url  = URL.createObjectURL(blob);
        const a    = document.createElement("a");
        a.href     = url;
        a.download = `honeytrap-ioc-ossiqn-${new Date().toISOString().split("T")[0]}.json`;
        a.click();
        URL.revokeObjectURL(url);
        termLog("SYS", `[${PRODUCER}] IOC exported — ${data.total_iocs || 0} records`);
    } catch(e) {
        termLog("ERR", `[${PRODUCER}] Export failed: ${e.message}`);
    }
}

function filterByTrap(trap) {
    state.trapFilter  = trap;
    state.currentPage = 1;
    document.querySelectorAll(".filter-item").forEach(el => el.classList.remove("active"));
    termLog("FILTER", `[${PRODUCER}] Trap filter: ${trap || "ALL"}`);
    refreshAttacks();
}

function filterBySeverity(severity) {
    state.severityFilter = severity;
    state.currentPage    = 1;
    document.querySelectorAll(".sev-item").forEach(el => el.classList.remove("active"));
    termLog("FILTER", `[${PRODUCER}] Severity filter: ${severity || "ALL"}`);
    refreshAttacks();
}

function switchTab(tab) {
    state.activeTab = tab;
    document.querySelectorAll(".tab-content").forEach(el => el.style.display = "none");
    document.querySelectorAll(".tab").forEach(el => el.classList.remove("active"));
    document.getElementById(`tab-${tab}`).style.display = "block";
    document.querySelectorAll(".tab").forEach(el => {
        if (el.textContent.toLowerCase().includes(tab)) el.classList.add("active");
    });
}

function changePage(dir) {
    const next = state.currentPage + dir;
    if (next < 1) return;
    state.currentPage = next;
    refreshAttacks();
    document.querySelector(".tab-content").scrollTop = 0;
}

function termLog(prefix, message) {
    const el     = document.getElementById("terminalLog");
    const colors = {SYS:"var(--text2)",FIND:"var(--medium)",WARN:"var(--high)",ERR:"var(--critical)",FILTER:"var(--cyan)"};
    const ts     = new Date().toLocaleTimeString("en-US", {hour12:false});
    el.innerHTML = `<span class="log-pre" style="color:${colors[prefix]||'var(--muted)'}">[${prefix}]</span><span style="color:var(--muted);margin-right:8px">${ts}</span>${escHtml(message)}`;
}

function updateClock() {
    const el = document.getElementById("headerTime");
    if (el) el.textContent = new Date().toUTCString().replace("GMT","UTC");
}

function escHtml(text) {
    if (!text) return "";
    const d = document.createElement("div");
    d.textContent = String(text);
    return d.innerHTML;
}

document.addEventListener("DOMContentLoaded", () => {
    console.log(`%c${TOOL} v${VERSION} — Produced by ${PRODUCER}`,"color:#aa44ff;font-size:14px;font-weight:bold;");
    console.log(`%cossiqn.com.tr`,"color:#ff2244;font-size:11px;");

    refreshAttacks();
    refreshStats();
    setInterval(updateClock, 1000);
    setInterval(refreshStats, 15000);
    setInterval(refreshAttacks, 30000);
    updateClock();

    termLog("SYS", `${TOOL} v${VERSION} initialized · Produced by ${PRODUCER} · ossiqn.com.tr`);
});