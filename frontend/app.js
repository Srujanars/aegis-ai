/**
 * AegisAI - Ultra-Modern Next-Gen Controller
 * Reactive Navigation, Presets, Split Terminal Stream, and Telemetry Engine
 */

const PRESETS = {
  db: `# Database connection & query performance task
db_uri = "postgres://analytics_admin:SuperSecretProdPass987@db.analytics.prod.internal:5432/core_users"

def fetch_top_customers():
    # Fix this slow query and optimize connection pooling
    query = "SELECT * FROM core_users WHERE balance > 100000;"
    return execute_query(db_uri, query)`,

  aws: `# Upload monthly financial audit report to private S3 bucket
import boto3

AWS_ACCESS_KEY = "AKIAIOSFODNN7EXAMPLE"
AWS_SECRET = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"

def upload_to_s3(file_path):
    s3 = boto3.client('s3', aws_access_key_id=AWS_ACCESS_KEY)
    s3.upload_file(file_path, 'company-confidential-audits', '2026_q3_report.pdf')`,

  pii: `# Customer verification routine complying with DPDP
customer_profile = {
    "name": "Vikramaditya Roy",
    "pan_number": "ABCDE1234F",
    "aadhaar_id": "9876-5432-1098",
    "email": "vikram.roy@personalmail.in",
    "credit_card": "4532789123456789"
}

# Write a python function to sanitize and hash customer records before saving to DB`,

  internal: `# Microservice communication setup
VPC_GATEWAY = "http://auth-service.payments.cluster.local:8080"
INTERNAL_ROUTER = "10.244.15.82"

def dispatch_payment_token(user_id):
    # Route request through private ingress controller
    response = requests.post(f"{VPC_GATEWAY}/api/v1/auth", json={"uid": user_id, "ip": INTERNAL_ROUTER})
    return response.json()`
};

// DOM References
const elements = {
  capsuleButtons: document.querySelectorAll(".capsule-btn"),
  tabViews: document.querySelectorAll(".tab-view"),
  promptInput: document.getElementById("promptInput"),
  btnIntercept: document.getElementById("btnIntercept"),
  aiPromptView: document.getElementById("aiPromptView"),
  rehydratedView: document.getElementById("rehydratedView"),
  threatChips: document.getElementById("threatChips"),
  threatsCountBadge: document.getElementById("threatsCountBadge"),
  rawRiskBadge: document.getElementById("rawRiskBadge"),
  eventsTableBody: document.getElementById("eventsTableBody"),
  dashTotalPrevented: document.getElementById("dashTotalPrevented"),
  dashCloudCreds: document.getElementById("dashCloudCreds"),
  dashPiiCount: document.getElementById("dashPiiCount")
};

document.addEventListener("DOMContentLoaded", () => {
  setupNavigation();
  loadPreset("db"); // Pre-load database test vector for instant demo readiness
  loadTelemetry();
});

// Setup Capsule Navigation
function setupNavigation() {
  elements.capsuleButtons.forEach(btn => {
    btn.addEventListener("click", () => {
      elements.capsuleButtons.forEach(b => b.classList.remove("active"));
      elements.tabViews.forEach(v => v.classList.remove("active"));

      btn.classList.add("active");
      const targetView = document.getElementById(btn.getAttribute("data-tab"));
      if (targetView) targetView.classList.add("active");

      if (btn.getAttribute("data-tab") === "tab-ciso-dash") {
        loadTelemetry();
      }
    });
  });

  elements.btnIntercept.addEventListener("click", executeInterception);
}

// Preset Loader
window.loadPreset = function(type, element) {
  if (element) {
    document.querySelectorAll(".preset-chip").forEach(c => c.classList.remove("active-preset"));
    element.classList.add("active-preset");
  }

  if (PRESETS[type]) {
    elements.promptInput.value = PRESETS[type];
    elements.rawRiskBadge.innerText = "UNENCRYPTED SECRETS";
    elements.rawRiskBadge.className = "security-state-tag danger";
  }
};

window.clearPreset = function(element) {
  if (element) {
    document.querySelectorAll(".preset-chip").forEach(c => c.classList.remove("active-preset"));
  }
  elements.promptInput.value = "";
  elements.aiPromptView.innerText = "// Ready for input";
  elements.rehydratedView.innerText = "// Ready for input";
  elements.threatChips.innerHTML = '<div style="color:var(--text-muted); font-size:0.85rem;">No active threats intercepted.</div>';
  elements.threatsCountBadge.innerText = "0 THREATS INTERCEPTED";
  elements.threatsCountBadge.style.background = "#334155";
};

// Execute Real-Time Two-Way Interception
async function executeInterception() {
  const prompt = elements.promptInput.value.trim();
  if (!prompt) {
    alert("Please enter a code snippet or prompt to test.");
    return;
  }

  elements.btnIntercept.innerHTML = "<span>⚡ Scrubbing Stream...</span>";
  elements.btnIntercept.disabled = true;

  try {
    const res = await fetch("/api/intercept", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        prompt: prompt,
        user: "developer-shiv",
        model: "OpenAI ChatGPT-4o"
      })
    });

    const data = await res.json();

    // 1. Stage 02: What Leaves the Machine (Wire View)
    elements.aiPromptView.innerText = data.ai_received_prompt;

    // 2. Stage 03: Re-hydrated Solution (Local Terminal)
    elements.rehydratedView.innerText = data.rehydrated_solution;

    // 3. Update Threat Telemetry HUD Chips
    const threats = data.threats_detected || [];
    elements.threatsCountBadge.innerText = `${threats.length} THREATS INTERCEPTED`;
    elements.threatsCountBadge.style.background = threats.length > 0 ? "#ef4444" : "#10b981";

    if (threats.length === 0) {
      elements.threatChips.innerHTML = '<div style="color:#10b981; font-size:0.85rem; font-family:var(--font-mono);">✔ Clean payload. Zero credential or PII leaks detected.</div>';
    } else {
      elements.threatChips.innerHTML = threats.map(t => `
        <div class="threat-pill-card">
          <span class="threat-severity-badge">${t.severity}</span>
          <div>
            <strong style="color:#ffffff; font-size:0.88rem; display:block;">${t.type}</strong>
            <span style="font-size:0.75rem; color:#94a3b8; font-family:var(--font-mono);">CAT: ${t.category}</span>
          </div>
        </div>
      `).join("");
    }

  } catch (err) {
    console.error("Interception error:", err);
  } finally {
    elements.btnIntercept.innerHTML = "<span>⚡ Execute Interception</span>";
    elements.btnIntercept.disabled = false;
  }
}

// Fetch CISO Dashboard Telemetry
async function loadTelemetry() {
  try {
    const res = await fetch("/api/telemetry");
    const data = await res.json();

    elements.dashTotalPrevented.innerText = data.total_intercepted;
    elements.dashCloudCreds.innerText = data.threats_prevented["Cloud Credentials"] || 0;
    elements.dashPiiCount.innerText = data.threats_prevented["Financial / PII"] || 0;

    const events = data.recent_events || [];
    elements.eventsTableBody.innerHTML = events.slice(0, 10).map(evt => `
      <tr>
        <td style="color:#cbd5e1; font-family:var(--font-mono); font-size:0.8rem;">${evt.timestamp}</td>
        <td><strong style="color:#38bdf8;">${evt.user}</strong></td>
        <td>${evt.entity_type}</td>
        <td>${evt.category}</td>
        <td>
          <span class="threat-severity-badge" style="background:${evt.severity === 'CRITICAL' ? 'rgba(239,68,68,0.2)' : 'rgba(245,158,11,0.2)'}; color:${evt.severity === 'CRITICAL' ? '#fca5a5' : '#fcd34d'}; border-color:${evt.severity === 'CRITICAL' ? '#ef4444' : '#f59e0b'};">
            ${evt.severity}
          </span>
        </td>
        <td style="color:#00f2fe; font-family:var(--font-mono); font-size:0.8rem;">${evt.model_target}</td>
      </tr>
    `).join("");

  } catch (err) {
    console.error("Telemetry fetch error:", err);
  }
}
