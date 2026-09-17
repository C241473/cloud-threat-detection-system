// Cloud Security Monitoring & Threat Detection System - Dashboard JS Engine

let severityChart = null;

document.addEventListener("DOMContentLoaded", () => {
  initCharts();
  refreshDashboard();
  // Poll every 4 seconds for live metric updates
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

    document.getElementById("val-total-events").innerText = data.total_events.toLocaleString();
    document.getElementById("val-failed-logins").innerText = data.failed_logins.toLocaleString();
    document.getElementById("val-total-threats").innerText = data.total_threats.toLocaleString();
    document.getElementById("val-active-threats").innerText = data.active_threats.toLocaleString();

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

    // Update Severity Chart
    if (severityChart) {
      const sev = data.threats_by_severity;
      severityChart.data.datasets[0].data = [
        sev.LOW || 0,
        sev.MEDIUM || 0,
        sev.HIGH || 0,
        sev.CRITICAL || 0
      ];
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
    const threats = await res.json();

    const tbody = document.getElementById("threats-table-body");
    if (!threats || threats.length === 0) {
      tbody.innerHTML = `<tr><td colspan="8" style="text-align: center; color: var(--text-secondary);">No threat alerts found matching current filters.</td></tr>`;
      return;
    }

    tbody.innerHTML = threats.map(t => {
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
    const logs = await res.json();

    const tbody = document.getElementById("logs-table-body");
    if (!logs || logs.length === 0) {
      tbody.innerHTML = `<tr><td colspan="6" style="text-align: center; color: var(--text-secondary);">No logs recorded.</td></tr>`;
      return;
    }

    tbody.innerHTML = logs.map(l => {
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
  try {
    await fetch(`/api/threats/${threatId}/status`, {
      method: "PATCH",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ status: "RESOLVED" })
    });
    refreshDashboard();
  } catch (err) {
    console.error("Failed to resolve threat:", err);
  }
}

// Simulations
async function triggerBruteForceSim() {
  const ip = `192.168.1.${Math.floor(Math.random() * 200) + 10}`;
  await fetch(`/api/logs/simulate/brute-force?ip_address=${ip}`, { method: "POST" });
  refreshDashboard();
}

async function triggerSQLiSim() {
  const ip = `198.51.100.${Math.floor(Math.random() * 200) + 10}`;
  await fetch(`/api/logs/simulate/sqli?ip_address=${ip}`, { method: "POST" });
  refreshDashboard();
}

async function triggerNormalLogin() {
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
  refreshDashboard();
}

async function triggerAccessDenied() {
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
  refreshDashboard();
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
