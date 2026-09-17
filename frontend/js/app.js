// Cloud Security Monitoring & Threat Detection System - Robust Dashboard JS Engine

let severityChart = null;

// Client-side state tracking for instant Vercel serverless UI responsiveness
let localState = {
  totalEventsOffset: 0,
  failedLoginsOffset: 0,
  threatsOffset: 0,
  activeThreatsOffset: 0,
  localThreats: [],
  localLogs: []
};

document.addEventListener("DOMContentLoaded", () => {
  initCharts();
  refreshDashboard();
  // Poll every 4 seconds for backend sync
  setInterval(refreshDashboard, 4000);
});

function refreshDashboard() {
  fetchDashboardStats();
  fetchThreats();
  fetchLogs();
}

// Fetch Main Metrics Summary
async function fetchDashboardStats() {
  try {
    const res = await fetch("/api/dashboard/stats");
    const data = await res.json();

    const totalEvents = (data.total_events || 0) + localState.totalEventsOffset;
    const failedLogins = (data.failed_logins || 0) + localState.failedLoginsOffset;
    const totalThreats = (data.total_threats || 0) + localState.threatsOffset;
    const activeThreats = Math.max(0, (data.active_threats || 0) + localState.activeThreatsOffset);

    document.getElementById("val-total-events").innerText = totalEvents.toLocaleString();
    document.getElementById("val-failed-logins").innerText = failedLogins.toLocaleString();
    document.getElementById("val-total-threats").innerText = totalThreats.toLocaleString();
    document.getElementById("val-active-threats").innerText = activeThreats.toLocaleString();

    // Hardware Metrics
    const cpu = Math.round(data.system_metrics.cpu_percent || 0);
    const mem = Math.round(data.system_metrics.memory_percent || 0);
    const disk = Math.round(data.system_metrics.disk_percent || 0);

    document.getElementById("cpu-val").innerText = `${cpu}%`;
    document.getElementById("cpu-bar").style.width = `${cpu}%`;

    document.getElementById("mem-val").innerText = `${mem}%`;
    document.getElementById("mem-bar").style.width = `${mem}%`;

    document.getElementById("disk-val").innerText = `${disk}%`;
    document.getElementById("disk-bar").style.width = `${disk}%`;

    // Dynamic Chart Update
    if (severityChart) {
      const sev = data.threats_by_severity || {};
      let low = sev.LOW || 0;
      let med = sev.MEDIUM || 0;
      let high = sev.HIGH || 0;
      let crit = sev.CRITICAL || 0;

      // Add local state severity counters
      localState.localThreats.forEach(t => {
        if (t.severity === "HIGH") high++;
        if (t.severity === "CRITICAL") crit++;
        if (t.severity === "MEDIUM") med++;
        if (t.severity === "LOW") low++;
      });

      severityChart.data.datasets[0].data = [low, med, high, crit];
      severityChart.update();
    }
  } catch (err) {
    console.error("Error fetching dashboard stats:", err);
  }
}

// Fetch Threats Table
async function fetchThreats() {
  try {
    const severity = document.getElementById("threat-severity-filter").value;
    const status = document.getElementById("threat-status-filter").value;

    const url = `/api/threats?severity=${severity}&status=${status}&limit=20`;
    const res = await fetch(url);
    const apiThreats = await res.json();

    let allThreats = [...localState.localThreats, ...(apiThreats || [])];

    // Apply Client Filters
    if (severity && severity !== "ALL") {
      allThreats = allThreats.filter(t => t.severity.toUpperCase() === severity.toUpperCase());
    }
    if (status && status !== "ALL") {
      allThreats = allThreats.filter(t => t.status.toUpperCase() === status.toUpperCase());
    }

    const tbody = document.getElementById("threats-table-body");
    if (!allThreats || allThreats.length === 0) {
      tbody.innerHTML = `<tr><td colspan="8" style="text-align: center; color: var(--text-secondary);">No threat alerts found matching current filters.</td></tr>`;
      return;
    }

    tbody.innerHTML = allThreats.map(t => {
      const sevClass = `badge-${t.severity.toLowerCase()}`;
      const statusClass = t.status === "ACTIVE" ? "badge-active" : "badge-resolved";
      const dateStr = new Date(t.detected_at).toLocaleTimeString();

      return `
        <tr>
          <td><strong>#${t.id}</strong></td>
          <td><code>${t.ip_address}</code></td>
          <td style="font-weight: 600;">${t.threat_type}</td>
          <td><span class="badge ${sevClass}">${t.severity}</span></td>
          <td style="max-width: 320px;">${t.description}</td>
          <td style="color: var(--text-secondary);">${dateStr}</td>
          <td><span class="badge-status ${statusClass}">${t.status}</span></td>
          <td>
            ${t.status === "ACTIVE" ? 
              `<button class="btn btn-secondary" style="padding: 0.25rem 0.6rem; font-size: 0.75rem;" onclick="resolveThreat(${t.id})">Mark Resolved</button>` 
              : `<span style="color: var(--accent-green); font-size: 0.8rem;">✓ Resolved</span>`
            }
          </td>
        </tr>
      `;
    }).join("");

  } catch (err) {
    console.error("Error fetching threats:", err);
  }
}

// Fetch Telemetry Logs Table
async function fetchLogs() {
  try {
    const eventType = document.getElementById("log-event-filter").value;
    const url = `/api/logs?event_type=${eventType}&limit=15`;
    const res = await fetch(url);
    const apiLogs = await res.json();

    let allLogs = [...localState.localLogs, ...(apiLogs || [])];

    if (eventType && eventType !== "ALL") {
      allLogs = allLogs.filter(l => l.event_type.toUpperCase() === eventType.toUpperCase());
    }

    const tbody = document.getElementById("logs-table-body");
    if (!allLogs || allLogs.length === 0) {
      tbody.innerHTML = `<tr><td colspan="6" style="text-align: center; color: var(--text-secondary);">No logs recorded.</td></tr>`;
      return;
    }

    tbody.innerHTML = allLogs.map(l => {
      const dateStr = new Date(l.timestamp).toLocaleTimeString();
      const statusColor = l.status === "FAILED" ? "var(--accent-red)" : (l.status === "SUCCESS" ? "var(--accent-green)" : "var(--accent-yellow)");

      return `
        <tr>
          <td style="color: var(--text-secondary);">${dateStr}</td>
          <td><code>${l.ip_address}</code></td>
          <td>${l.username || '<em>anonymous</em>'}</td>
          <td><span style="font-weight: 600;">${l.event_type}</span></td>
          <td style="color: ${statusColor}; font-weight: 700;">${l.status}</td>
          <td style="color: var(--text-secondary);">${l.details || '-'}</td>
        </tr>
      `;
    }).join("");

  } catch (err) {
    console.error("Error fetching logs:", err);
  }
}

// IP Geolocation Inspector Lookup
async function lookupIPInfo() {
  const ip = document.getElementById("ip-lookup-input").value.trim() || "198.51.100.42";
  const resultDiv = document.getElementById("ip-lookup-result");

  try {
    const res = await fetch(`/api/logs/geo/${ip}`);
    const data = await res.json();

    resultDiv.style.display = "block";
    resultDiv.innerHTML = `
      <div style="display: flex; gap: 1rem; align-items: center; flex-wrap: wrap;">
        <span style="font-size: 2rem;">${data.flag}</span>
        <div>
          <h4 style="font-size: 1rem; font-weight: 700;">IP: <code>${data.ip}</code></h4>
          <p style="font-size: 0.85rem; color: var(--text-secondary);">
            <strong>Country:</strong> ${data.country} (${data.country_code}) | 
            <strong>Region:</strong> ${data.region} | 
            <strong>Network / ISP:</strong> ${data.isp}
          </p>
        </div>
      </div>
    `;
  } catch (err) {
    console.error("Failed to lookup IP:", err);
  }
}

// Resolve Threat
async function resolveThreat(threatId) {
  // Update local state threat status
  const found = localState.localThreats.find(t => t.id === threatId);
  if (found && found.status === "ACTIVE") {
    found.status = "RESOLVED";
    localState.activeThreatsOffset--;
  } else {
    localState.activeThreatsOffset--;
  }

  fetchDashboardStats();
  fetchThreats();

  try {
    await fetch(`/api/threats/${threatId}/status`, {
      method: "PATCH",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ status: "RESOLVED" })
    });
  } catch (err) {
    console.error("Failed to resolve threat API call:", err);
  }
}

// Interactive Attack Simulations with Guaranteed Instant UI Responsiveness
async function triggerBruteForceSim() {
  const ip = `192.168.1.${Math.floor(Math.random() * 200) + 10}`;
  const now = new Date().toISOString();

  // Instant Local State Increments
  localState.totalEventsOffset += 5;
  localState.failedLoginsOffset += 5;
  localState.threatsOffset += 1;
  localState.activeThreatsOffset += 1;

  const newThreatId = Math.floor(Math.random() * 9000) + 1000;
  localState.localThreats.unshift({
    id: newThreatId,
    ip_address: ip,
    threat_type: "Brute-Force Login Attempt",
    severity: "HIGH",
    description: `Detected 5 failed login attempts within 5 minutes from IP ${ip}.`,
    detected_at: now,
    status: "ACTIVE"
  });

  for (let i = 0; i < 5; i++) {
    localState.localLogs.unshift({
      id: Math.floor(Math.random() * 90000) + 10000,
      ip_address: ip,
      username: "admin",
      event_type: "LOGIN_FAILED",
      status: "FAILED",
      details: `Invalid password attempt #${i + 1}`,
      timestamp: now
    });
  }

  // Instant UI Re-render
  fetchDashboardStats();
  fetchThreats();
  fetchLogs();

  // Async API Call
  try {
    await fetch(`/api/logs/simulate/brute-force?ip_address=${ip}`, { method: "POST" });
  } catch (e) {}
}

async function triggerSQLiSim() {
  const ip = `198.51.100.${Math.floor(Math.random() * 200) + 10}`;
  const now = new Date().toISOString();

  localState.totalEventsOffset += 1;
  localState.threatsOffset += 1;
  localState.activeThreatsOffset += 1;

  const newThreatId = Math.floor(Math.random() * 9000) + 1000;
  localState.localThreats.unshift({
    id: newThreatId,
    ip_address: ip,
    threat_type: "SQL Injection / Malicious Payload Attack",
    severity: "CRITICAL",
    description: `Malicious code payload detected from IP ${ip}: '\' OR \'1\'=\'1\' -- UNION SELECT'`,
    detected_at: now,
    status: "ACTIVE"
  });

  localState.localLogs.unshift({
    id: Math.floor(Math.random() * 90000) + 10000,
    ip_address: ip,
    username: "hacker_x",
    event_type: "SUSPICIOUS_REQUEST",
    status: "FAILED",
    details: "Attempted SQLi payload: ' OR '1'='1' -- UNION SELECT",
    timestamp: now
  });

  fetchDashboardStats();
  fetchThreats();
  fetchLogs();

  try {
    await fetch(`/api/logs/simulate/sqli?ip_address=${ip}`, { method: "POST" });
  } catch (e) {}
}

async function triggerNormalLogin() {
  const now = new Date().toISOString();
  localState.totalEventsOffset += 1;

  localState.localLogs.unshift({
    id: Math.floor(Math.random() * 90000) + 10000,
    ip_address: "10.0.0.12",
    username: "authorized_user",
    event_type: "LOGIN_SUCCESS",
    status: "SUCCESS",
    details: "User logged in via Dashboard UI",
    timestamp: now
  });

  fetchDashboardStats();
  fetchLogs();

  try {
    await fetch("/api/logs", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        ip_address: "10.0.0.12",
        username: "authorized_user",
        event_type: "LOGIN_SUCCESS",
        status: "SUCCESS",
        details: "User logged in via Dashboard UI"
      })
    });
  } catch (e) {}
}

async function triggerAccessDenied() {
  const now = new Date().toISOString();
  localState.totalEventsOffset += 1;

  localState.localLogs.unshift({
    id: Math.floor(Math.random() * 90000) + 10000,
    ip_address: "172.16.0.88",
    username: "anonymous_guest",
    event_type: "ACCESS_DENIED",
    status: "FAILED",
    details: "Forbidden request to privileged route /admin/secrets",
    timestamp: now
  });

  fetchDashboardStats();
  fetchLogs();

  try {
    await fetch("/api/logs", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        ip_address: "172.16.0.88",
        username: "anonymous_guest",
        event_type: "ACCESS_DENIED",
        status: "FAILED",
        details: "Forbidden request to privileged route /admin/secrets"
      })
    });
  } catch (e) {}
}

// Initialize Charts
function initCharts() {
  const ctx = document.getElementById("threatSeverityChart").getContext("2d");
  severityChart = new Chart(ctx, {
    type: "doughnut",
    data: {
      labels: ["Low", "Medium", "High", "Critical"],
      datasets: [{
        data: [0, 0, 0, 0],
        backgroundColor: [
          "#10b981", // Green
          "#f59e0b", // Yellow
          "#ef4444", // Red
          "#8b5cf6"  // Purple
        ],
        borderWidth: 2,
        borderColor: "#1f2937"
      }]
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      plugins: {
        legend: {
          position: "right",
          labels: { color: "#9ca3af", font: { family: "Inter", size: 12 } }
        }
      }
    }
  });
}
