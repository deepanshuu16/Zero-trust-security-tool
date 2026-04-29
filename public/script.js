const loginForm = document.getElementById("login-form");
const otpForm = document.getElementById("otp-form");
const logoutBtn = document.getElementById("logout-btn");
const regenerateBtn = document.getElementById("regenerate-btn");

const loginMessage = document.getElementById("login-message");
const otpMessage = document.getElementById("otp-message");
const otpValue = document.getElementById("otp-value");
const otpDisplayValue = document.getElementById("otp-display-value");
const sessionStatus = document.getElementById("session-status");
const trustScore = document.getElementById("trust-score");
const ipAddress = document.getElementById("ip-address");
const networkZone = document.getElementById("network-zone");
const deviceType = document.getElementById("device-type");
const browserName = document.getElementById("browser-name");
const osName = document.getElementById("os-name");
const trustStatus = document.getElementById("trust-status");
const policyDecision = document.getElementById("policy-decision");
const sessionCreated = document.getElementById("session-created");
const lastSeen = document.getElementById("last-seen");
const otpUsage = document.getElementById("otp-usage");
const trustReasons = document.getElementById("trust-reasons");
const adminMonitor = document.getElementById("admin-monitor");
const adminActivityList = document.getElementById("admin-activity-list");

const sections = {
  admin: document.getElementById("admin-section"),
  employee: document.getElementById("employee-section"),
  guest: document.getElementById("guest-section")
};

const lists = {
  admin: document.getElementById("admin-list"),
  employee: document.getElementById("employee-list"),
  guest: document.getElementById("guest-list")
};

async function api(path, options = {}) {
  const response = await fetch(path, {
    headers: { "Content-Type": "application/json" },
    credentials: "same-origin",
    ...options
  });

  const data = await response.json();
  if (!response.ok) {
    throw new Error(data.error || "Request failed");
  }
  return data;
}

function formatTimestamp(value) {
  if (!value) {
    return "Pending";
  }

  const date = new Date(value);
  if (Number.isNaN(date.getTime())) {
    return value;
  }

  return date.toLocaleString();
}

function resetTelemetry() {
  trustScore.textContent = "Pending";
  ipAddress.textContent = "Pending";
  networkZone.textContent = "Pending";
  deviceType.textContent = "Pending";
  browserName.textContent = "Pending";
  osName.textContent = "Pending";
  trustStatus.textContent = "Pending";
  policyDecision.textContent = "Pending";
  sessionCreated.textContent = "Pending";
  lastSeen.textContent = "Pending";
  otpUsage.textContent = "0";
  trustReasons.innerHTML = "<li>Session analysis will appear here after login.</li>";
}

function renderTelemetry(context) {
  if (!context || !context.trust) {
    resetTelemetry();
    return;
  }

  trustScore.textContent = `${context.trust.score}/100`;
  ipAddress.textContent = context.trust.ipAddress;
  networkZone.textContent = context.trust.networkZone;
  deviceType.textContent = context.trust.deviceType;
  browserName.textContent = context.trust.browser;
  osName.textContent = context.trust.operatingSystem;
  trustStatus.textContent = context.trust.status;
  policyDecision.textContent = context.trust.policyDecision;
  sessionCreated.textContent = formatTimestamp(context.createdAt);
  lastSeen.textContent = formatTimestamp(context.lastSeenAt);
  otpUsage.textContent = String(context.otpUsageCount);
  trustReasons.innerHTML = "";

  context.trust.reasons.forEach((reason) => {
    const li = document.createElement("li");
    li.textContent = reason;
    trustReasons.appendChild(li);
  });
}

function clearRoleSections() {
  Object.values(sections).forEach((section) => section.classList.add("hidden"));
  Object.values(lists).forEach((list) => {
    list.innerHTML = "";
  });
}

function resetAdminMonitor() {
  adminMonitor.classList.add("hidden");
  adminActivityList.innerHTML = `
    <article class="activity-card empty-state">
      <h3>No activity yet</h3>
      <p>Recent employee and guest login events will appear here for the admin.</p>
    </article>
  `;
}

async function loadAdminActivity() {
  const data = await api("/api/admin/activity", { method: "GET" });
  const relevantEvents = data.events.filter((event) => event.role !== "admin");

  adminActivityList.innerHTML = "";
  if (!relevantEvents.length) {
    resetAdminMonitor();
    adminMonitor.classList.remove("hidden");
    return;
  }

  relevantEvents.forEach((event) => {
    const card = document.createElement("article");
    card.className = `activity-card activity-${event.role}`;
    card.innerHTML = `
      <div class="activity-topline">
        <span class="activity-badge">${event.role}</span>
        <span class="activity-time">${formatTimestamp(event.timestamp)}</span>
      </div>
      <h3>${event.name}</h3>
      <p>${event.username} completed ${event.eventType === "otp-verified" ? "OTP verification" : "login initiation"}.</p>
      <div class="activity-meta">
        <span>IP: ${event.ipAddress}</span>
        <span>${event.deviceType}</span>
        <span>${event.browser}</span>
        <span>${event.trustStatus} ${event.trustScore}/100</span>
      </div>
    `;
    adminActivityList.appendChild(card);
  });

  adminMonitor.classList.remove("hidden");
}

function renderRoleSections(role, sectionMap) {
  clearRoleSections();
  Object.entries(sectionMap).forEach(([sectionRole, sectionData]) => {
    const section = sections[sectionRole];
    const list = lists[sectionRole];
    if (!section || !list) {
      return;
    }

    sectionData.items.forEach((item) => {
      const li = document.createElement("li");
      li.textContent = item;
      list.appendChild(li);
    });
    section.classList.remove("hidden");
  });

  if (role !== "admin") {
    resetAdminMonitor();
  }
}

async function loadSession() {
  const data = await api("/api/session", { method: "GET" });
  if (!data.authenticated) {
    sessionStatus.textContent = "No verified user yet.";
    clearRoleSections();
    resetTelemetry();
    resetAdminMonitor();
    return;
  }

  renderTelemetry(data.context);

  if (!data.otpVerified) {
    sessionStatus.textContent = `${data.user.name} signed in as ${data.user.role}, waiting for OTP verification.`;
    clearRoleSections();
    resetAdminMonitor();
    return;
  }

  const access = await api("/api/access", { method: "GET" });
  renderTelemetry(access.context);
  sessionStatus.textContent = `${data.user.name} is verified and active in the ${data.user.role} section.`;
  renderRoleSections(access.role, access.sections);

  if (access.role === "admin") {
    await loadAdminActivity();
  }
}

loginForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  loginMessage.textContent = "";
  otpMessage.textContent = "";

  const formData = new FormData(loginForm);
  const payload = Object.fromEntries(formData.entries());

  try {
    const data = await api("/api/login", {
      method: "POST",
      body: JSON.stringify(payload)
    });

    otpValue.textContent = data.otp;
    otpDisplayValue.textContent = data.otp;
    loginMessage.textContent = `${data.message} Signed in as ${data.role}.`;
    sessionStatus.textContent = `${data.name} signed in as ${data.role}, waiting for OTP verification.`;
    renderTelemetry(data.context);
    clearRoleSections();
    resetAdminMonitor();
  } catch (error) {
    loginMessage.textContent = error.message;
  }
});

otpForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  otpMessage.textContent = "";

  try {
    const otp = document.getElementById("otp-input").value;
    const data = await api("/api/otp/verify", {
      method: "POST",
      body: JSON.stringify({ otp })
    });

    otpValue.textContent = "Used";
    otpDisplayValue.textContent = "Used";
    otpMessage.textContent = data.message;
    renderTelemetry(data.context);
    document.getElementById("otp-input").value = "";
    await loadSession();
  } catch (error) {
    otpMessage.textContent = error.message;
  }
});

regenerateBtn.addEventListener("click", async () => {
  otpMessage.textContent = "";
  try {
    const data = await api("/api/otp/regenerate", {
      method: "POST",
      body: JSON.stringify({})
    });

    otpValue.textContent = data.otp;
    otpDisplayValue.textContent = data.otp;
    otpMessage.textContent = `${data.message} Request count: ${data.otpUsageCount}.`;
    renderTelemetry(data.context);
  } catch (error) {
    otpMessage.textContent = error.message;
  }
});

logoutBtn.addEventListener("click", async () => {
  loginMessage.textContent = "";
  otpMessage.textContent = "";
  await api("/api/logout", { method: "POST", body: JSON.stringify({}) });
  otpValue.textContent = "Not generated yet";
  otpDisplayValue.textContent = "Not generated yet";
  sessionStatus.textContent = "No verified user yet.";
  resetTelemetry();
  clearRoleSections();
  resetAdminMonitor();
});

loadSession().catch((error) => {
  sessionStatus.textContent = error.message;
  resetTelemetry();
  resetAdminMonitor();
});
