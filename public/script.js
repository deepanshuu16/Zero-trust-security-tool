const STORAGE_KEY = "securevault-zero-trust-demo";

const loginForm = document.getElementById("login-form");
const otpForm = document.getElementById("otp-form");
const logoutBtn = document.getElementById("logout-btn");
const regenerateBtn = document.getElementById("regenerate-btn");

const simulateBruteforceBtn = document.getElementById("simulate-bruteforce");
const simulateTokenTheftBtn = document.getElementById("simulate-token-theft");
const simulateLocationBtn = document.getElementById("simulate-location");
const clearIncidentsBtn = document.getElementById("clear-incidents");

const workspaceRoot = document.getElementById("app-workspace");
const workspaceUserName = document.getElementById("workspace-user-name");
const workspaceUserRole = document.getElementById("workspace-user-role");
const workspaceTrustScore = document.getElementById("workspace-trust-score");
const workspaceDocCount = document.getElementById("workspace-doc-count");
const vaultQuickStatus = document.getElementById("vault-quick-status");
const appIdentityStatus = document.getElementById("app-identity-status");
const appPolicyMode = document.getElementById("app-policy-mode");
const appNetworkZone = document.getElementById("app-network-zone");
const vaultBanner = document.getElementById("vault-banner");
const vaultSecretPanel = document.getElementById("vault-secret-panel");
const vaultSecretText = document.getElementById("vault-secret-text");
const vaultSetForm = document.getElementById("vault-set-form");
const vaultUnlockForm = document.getElementById("vault-unlock-form");
const vaultLockBtn = document.getElementById("vault-lock-btn");
const vaultSetMessage = document.getElementById("vault-set-message");
const vaultUnlockMessage = document.getElementById("vault-unlock-message");
const documentForm = document.getElementById("document-form");
const documentInput = document.getElementById("document-input");
const documentNote = document.getElementById("document-note");
const documentMessage = document.getElementById("document-message");
const documentList = document.getElementById("document-list");
const workspaceNavButtons = Array.from(document.querySelectorAll(".workspace-nav-btn"));
const workspaceViews = Array.from(document.querySelectorAll(".workspace-view"));
const adminOnlyNavButtons = Array.from(document.querySelectorAll(".admin-only"));

const loginMessage = document.getElementById("login-message");
const otpMessage = document.getElementById("otp-message");
const simMessage = document.getElementById("sim-message");
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
const alertFeed = document.getElementById("alert-feed");
const securityPostureScore = document.getElementById("security-posture-score");
const identityBar = document.getElementById("identity-bar");
const monitoringBar = document.getElementById("monitoring-bar");
const resistanceBar = document.getElementById("resistance-bar");
const kpiActiveSessions = document.getElementById("kpi-active-sessions");
const kpiSuspiciousEvents = document.getElementById("kpi-suspicious-events");
const kpiBlockedActions = document.getElementById("kpi-blocked-actions");
const kpiRiskLevel = document.getElementById("kpi-risk-level");
const cursorGlow = document.getElementById("cursor-glow");

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

const users = {
  admin: {
    username: "admin",
    password: "Admin@123",
    role: "admin",
    name: "Primary Administrator"
  },
  employee: {
    username: "employee",
    password: "Employee@123",
    role: "employee",
    name: "Operations Employee"
  },
  guest: {
    username: "guest",
    password: "Guest@123",
    role: "guest",
    name: "Visitor Guest"
  }
};

const roleContent = {
  admin: {
    items: [
      "Approve or block high-risk access requests",
      "Review live OTP issuance metrics and attack activity",
      "Monitor guest and employee sessions with policy visibility",
      "Enforce least-privilege decisions across all roles"
    ]
  },
  employee: {
    items: [
      "Access internal tools only after continuous verification",
      "Confirm device trust before opening sensitive resources",
      "Request temporary elevation under monitored conditions",
      "Stay restricted from administrative control surfaces"
    ]
  },
  guest: {
    items: [
      "Use time-limited isolated access with minimal privileges",
      "Enter approved shared resources only",
      "Trigger stronger monitoring on suspicious behavior",
      "Remain blocked from internal administrative systems"
    ]
  }
};

let activeWorkspaceView = "overview";

function defaultState() {
  return {
    session: null,
    events: [],
    incidents: [],
    userData: {}
  };
}

function normalizeState(rawState) {
  const baseState = defaultState();
  const nextState = rawState && typeof rawState === "object" ? rawState : {};
  return {
    session: nextState.session || baseState.session,
    events: Array.isArray(nextState.events) ? nextState.events : baseState.events,
    incidents: Array.isArray(nextState.incidents) ? nextState.incidents : baseState.incidents,
    userData: nextState.userData && typeof nextState.userData === "object" ? nextState.userData : baseState.userData
  };
}

function readState() {
  try {
    return normalizeState(JSON.parse(localStorage.getItem(STORAGE_KEY)));
  } catch {
    return defaultState();
  }
}

function writeState(nextState) {
  localStorage.setItem(STORAGE_KEY, JSON.stringify(normalizeState(nextState)));
}

function nowIso() {
  return new Date().toISOString();
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

function summarizeOS(agent) {
  const ua = agent.toLowerCase();
  if (ua.includes("windows")) {
    return "Windows";
  }
  if (ua.includes("mac os") || ua.includes("macintosh")) {
    return "macOS";
  }
  if (ua.includes("android")) {
    return "Android";
  }
  if (ua.includes("iphone") || ua.includes("ipad") || ua.includes("ios")) {
    return "iOS";
  }
  if (ua.includes("linux")) {
    return "Linux";
  }
  return "Unknown OS";
}

function summarizeBrowser(agent) {
  const ua = agent.toLowerCase();
  if (ua.includes("edg/")) {
    return "Microsoft Edge";
  }
  if (ua.includes("chrome/") && !ua.includes("edg/")) {
    return "Google Chrome";
  }
  if (ua.includes("firefox/")) {
    return "Mozilla Firefox";
  }
  if (ua.includes("safari/") && !ua.includes("chrome/")) {
    return "Safari";
  }
  return "Unknown Browser";
}

function summarizeDevice(agent) {
  const ua = agent.toLowerCase();
  if (ua.includes("ipad") || ua.includes("tablet")) {
    return "Tablet";
  }
  if (ua.includes("mobile") || ua.includes("android") || ua.includes("iphone")) {
    return "Mobile Device";
  }
  return "Desktop";
}

function generateOtp(previousOtp) {
  let otp = "";
  do {
    otp = `${Math.floor(100000 + Math.random() * 900000)}`;
  } while (otp === previousOtp);
  return otp;
}

function buildTrustContext(user) {
  const userAgent = navigator.userAgent || "Unknown Agent";
  const device = summarizeDevice(userAgent);
  const browser = summarizeBrowser(userAgent);
  const operatingSystem = summarizeOS(userAgent);

  let score = 58;
  const reasons = [
    "Continuous verification checks role, device, and browser context",
    "Assume-breach posture limits access based on session risk",
    "Public web session is treated as untrusted until proven otherwise"
  ];

  if (device === "Desktop") {
    score += 10;
    reasons.push("Desktop device profile is considered lower risk");
  } else {
    reasons.push("Non-desktop device requires closer review");
  }

  if (user.role === "admin") {
    score -= 5;
    reasons.push("Admin sessions require stricter scrutiny");
  } else if (user.role === "employee") {
    score += 5;
    reasons.push("Employee role matches standard internal access policy");
  } else {
    score -= 8;
    reasons.push("Guest role remains restricted by Zero Trust policy");
  }

  score = Math.max(0, Math.min(100, score));

  let status = "Restricted";
  let policy = "Access limited to the minimum required role scope.";
  if (score >= 75) {
    status = "Trusted";
    policy = "Full role access granted after OTP verification.";
  } else if (score >= 60) {
    status = "Elevated Review";
    policy = "Access granted with additional monitoring.";
  }

  return {
    ipAddress: "Browser-side live demo",
    userAgent,
    deviceType: device,
    browser,
    operatingSystem,
    networkZone: "Public Web Session",
    score,
    status,
    policyDecision: policy,
    reasons
  };
}

function buildSession(user, previousSession) {
  const timestamp = nowIso();
  const trust = buildTrustContext(user);
  return {
    username: user.username,
    name: user.name,
    role: user.role,
    otpVerified: false,
    otp: generateOtp(previousSession ? previousSession.otp : null),
    createdAt: timestamp,
    lastSeenAt: timestamp,
    otpIssuedAt: timestamp,
    otpUsageCount: previousSession ? previousSession.otpUsageCount + 1 : 1,
    trust
  };
}

function getUserStore(state, username) {
  if (!state.userData[username]) {
    state.userData[username] = {
      documents: [],
      vaultKey: null,
      vaultUnlocked: false
    };
  }
  if (!Array.isArray(state.userData[username].documents)) {
    state.userData[username].documents = [];
  }
  if (!Object.prototype.hasOwnProperty.call(state.userData[username], "vaultKey")) {
    state.userData[username].vaultKey = null;
  }
  if (!Object.prototype.hasOwnProperty.call(state.userData[username], "vaultUnlocked")) {
    state.userData[username].vaultUnlocked = false;
  }
  return state.userData[username];
}

function recordEvent(state, session, eventType, extra = {}) {
  state.events.unshift({
    timestamp: nowIso(),
    eventType,
    username: session.username,
    name: session.name,
    role: session.role,
    ipAddress: session.trust.ipAddress,
    deviceType: session.trust.deviceType,
    browser: session.trust.browser,
    trustStatus: session.trust.status,
    trustScore: session.trust.score,
    ...extra
  });
  state.events = state.events.slice(0, 60);
}

function recordIncident(state, incident) {
  state.incidents.unshift({
    id: `${incident.type}-${Date.now()}`,
    timestamp: nowIso(),
    severity: incident.severity,
    type: incident.type,
    title: incident.title,
    description: incident.description,
    blocked: incident.blocked
  });
  state.incidents = state.incidents.slice(0, 20);
}

function setWorkspaceView(viewName) {
  activeWorkspaceView = viewName;

  workspaceNavButtons.forEach((button) => {
    const isActive = button.dataset.view === viewName;
    button.classList.toggle("active", isActive);
  });

  workspaceViews.forEach((panel) => {
    panel.classList.toggle("active", panel.dataset.viewPanel === viewName);
  });
}

function updateWorkspaceHeader(session, state) {
  if (!session || !session.otpVerified) {
    workspaceUserName.textContent = "No active user";
    workspaceUserRole.textContent = "Login required";
    workspaceTrustScore.textContent = "Pending";
    workspaceDocCount.textContent = "0";
    vaultQuickStatus.textContent = "Locked";
    appIdentityStatus.textContent = "Pending";
    appPolicyMode.textContent = "Pending";
    appNetworkZone.textContent = "Pending";
    return;
  }

  const userStore = getUserStore(state, session.username);
  workspaceUserName.textContent = session.name;
  workspaceUserRole.textContent = `${session.role.toUpperCase()} workspace`;
  workspaceTrustScore.textContent = `${session.trust.score}/100`;
  workspaceDocCount.textContent = String(userStore.documents.length);
  vaultQuickStatus.textContent = userStore.vaultUnlocked ? "Unlocked" : userStore.vaultKey ? "Locked" : "Not set";
  appIdentityStatus.textContent = session.trust.status;
  appPolicyMode.textContent = session.trust.policyDecision;
  appNetworkZone.textContent = session.trust.networkZone;
}

function renderDocuments(session, state) {
  documentList.innerHTML = "";

  if (!session || !session.otpVerified) {
    documentList.innerHTML = `
      <article class="document-card empty-state">
        <h3>Login required</h3>
        <p>Verify a user session to work with uploaded files.</p>
      </article>
    `;
    return;
  }

  if (session.role === "guest") {
    documentList.innerHTML = `
      <article class="document-card empty-state">
        <h3>Guest restrictions active</h3>
        <p>Guest accounts cannot upload work files in this least-privilege demo flow.</p>
      </article>
    `;
    return;
  }

  const userStore = getUserStore(state, session.username);
  if (!userStore.documents.length) {
    documentList.innerHTML = `
      <article class="document-card empty-state">
        <h3>No documents yet</h3>
        <p>Uploaded files will appear here for the signed-in employee or admin.</p>
      </article>
    `;
    return;
  }

  userStore.documents.forEach((documentEntry) => {
    const card = document.createElement("article");
    card.className = "document-card";
    card.innerHTML = `
      <div class="document-topline">
        <strong>${documentEntry.fileName}</strong>
        <span>${documentEntry.fileSize}</span>
      </div>
      <p>${documentEntry.note || "No note added for this upload."}</p>
      <div class="document-meta">
        <span>Owner: ${documentEntry.ownerRole}</span>
        <span>${formatTimestamp(documentEntry.uploadedAt)}</span>
      </div>
    `;
    documentList.appendChild(card);
  });
}

function renderVault(session, state) {
  if (!session || !session.otpVerified) {
    vaultBanner.textContent = "Set your private vault key";
    vaultQuickStatus.textContent = "Locked";
    vaultSecretPanel.classList.add("hidden");
    return;
  }

  const userStore = getUserStore(state, session.username);
  if (!userStore.vaultKey) {
    vaultBanner.textContent = "Set your private vault key";
  } else if (userStore.vaultUnlocked) {
    vaultBanner.textContent = "Vault unlocked";
  } else {
    vaultBanner.textContent = "Vault ready to unlock";
  }

  vaultQuickStatus.textContent = userStore.vaultUnlocked ? "Unlocked" : userStore.vaultKey ? "Locked" : "Not set";
  vaultSecretText.textContent = `${session.name} can use this vault space for browser-local confidential notes and protected demo content.`;
  vaultSecretPanel.classList.toggle("hidden", !userStore.vaultUnlocked);
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

function renderTelemetry(session) {
  if (!session || !session.trust) {
    resetTelemetry();
    return;
  }

  trustScore.textContent = `${session.trust.score}/100`;
  ipAddress.textContent = session.trust.ipAddress;
  networkZone.textContent = session.trust.networkZone;
  deviceType.textContent = session.trust.deviceType;
  browserName.textContent = session.trust.browser;
  osName.textContent = session.trust.operatingSystem;
  trustStatus.textContent = session.trust.status;
  policyDecision.textContent = session.trust.policyDecision;
  sessionCreated.textContent = formatTimestamp(session.createdAt);
  lastSeen.textContent = formatTimestamp(session.lastSeenAt);
  otpUsage.textContent = String(session.otpUsageCount);
  trustReasons.innerHTML = "";

  session.trust.reasons.forEach((reason) => {
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
  adminActivityList.innerHTML = `
    <article class="activity-card empty-state">
      <h3>No activity yet</h3>
      <p>Recent employee and guest login events will appear here for the admin.</p>
    </article>
  `;
}

function renderRoleSections(role) {
  clearRoleSections();
  const visibleRoles = role === "admin" ? ["admin", "employee", "guest"] : [role];

  visibleRoles.forEach((visibleRole) => {
    const section = sections[visibleRole];
    const list = lists[visibleRole];
    const content = roleContent[visibleRole];
    if (!section || !list || !content) {
      return;
    }

    content.items.forEach((item) => {
      const li = document.createElement("li");
      li.textContent = item;
      list.appendChild(li);
    });
    section.classList.remove("hidden");
  });
}

function renderAdminActivity(events) {
  const relevantEvents = events.filter((event) => event.role !== "admin");
  adminActivityList.innerHTML = "";

  if (!relevantEvents.length) {
    resetAdminMonitor();
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
        <span>Source: ${event.ipAddress}</span>
        <span>${event.deviceType}</span>
        <span>${event.browser}</span>
        <span>${event.trustStatus} ${event.trustScore}/100</span>
      </div>
    `;
    adminActivityList.appendChild(card);
  });
}

function renderAlertFeed(state) {
  const feedItems = [];

  state.incidents.forEach((incident) => {
    feedItems.push({
      severity: incident.severity,
      title: incident.title,
      description: `${incident.description} - ${formatTimestamp(incident.timestamp)}`
    });
  });

  if (state.session) {
    feedItems.push({
      severity: "info",
      title: `${state.session.name} session ${state.session.otpVerified ? "verified" : "awaiting OTP"}`,
      description: `${state.session.role} access evaluated with trust status ${state.session.trust.status}.`
    });
  }

  if (!feedItems.length) {
    feedItems.push({
      severity: "info",
      title: "System ready",
      description: "No incidents yet. Use the attack simulator below or sign in to generate activity."
    });
  }

  alertFeed.innerHTML = "";
  feedItems.slice(0, 6).forEach((item) => {
    const wrapper = document.createElement("div");
    wrapper.className = `alert-item ${item.severity}`;
    wrapper.innerHTML = `
      <span class="alert-status"></span>
      <div>
        <strong>${item.title}</strong>
        <p>${item.description}</p>
      </div>
    `;
    alertFeed.appendChild(wrapper);
  });
}

function renderKpis(state) {
  const activeSessions = state.session && state.session.otpVerified ? 1 : 0;
  const suspiciousEvents = state.incidents.length;
  const blockedActions = state.incidents.filter((incident) => incident.blocked).length;
  const riskLevel = suspiciousEvents >= 3 ? "Critical" : suspiciousEvents >= 2 ? "High" : suspiciousEvents >= 1 ? "Elevated" : "Low";

  kpiActiveSessions.textContent = String(activeSessions);
  kpiSuspiciousEvents.textContent = String(suspiciousEvents);
  kpiBlockedActions.textContent = String(blockedActions);
  kpiRiskLevel.textContent = riskLevel;

  let posture = 92;
  posture -= suspiciousEvents * 9;
  posture -= blockedActions * 4;
  posture = Math.max(42, posture);

  securityPostureScore.textContent = String(posture);
  identityBar.style.width = `${Math.max(40, posture)}%`;
  monitoringBar.style.width = `${Math.max(35, 84 - suspiciousEvents * 9)}%`;
  resistanceBar.style.width = `${Math.max(30, 78 - blockedActions * 8)}%`;
}

function renderWorkspace(state) {
  const session = state.session;
  const verified = Boolean(session && session.otpVerified);
  workspaceRoot.classList.toggle("hidden", !verified);

  if (!verified) {
    updateWorkspaceHeader(null, state);
    renderDocuments(null, state);
    renderVault(null, state);
    adminOnlyNavButtons.forEach((button) => button.classList.add("hidden"));
    setWorkspaceView("overview");
    return;
  }

  updateWorkspaceHeader(session, state);
  renderVault(session, state);
  renderDocuments(session, state);
  renderRoleSections(session.role);

  if (session.role === "admin") {
    adminOnlyNavButtons.forEach((button) => button.classList.remove("hidden"));
    renderAdminActivity(state.events);
  } else {
    adminOnlyNavButtons.forEach((button) => button.classList.add("hidden"));
    if (activeWorkspaceView === "monitor") {
      setWorkspaceView("overview");
    }
    resetAdminMonitor();
  }
}

function renderSession() {
  const state = readState();
  const session = state.session;

  renderAlertFeed(state);
  renderKpis(state);

  if (!session) {
    otpValue.textContent = "Not generated yet";
    otpDisplayValue.textContent = "Not generated yet";
    sessionStatus.textContent = "No verified user yet.";
    clearRoleSections();
    resetTelemetry();
    resetAdminMonitor();
    renderWorkspace(state);
    return;
  }

  otpValue.textContent = session.otpVerified ? "Used" : session.otp;
  otpDisplayValue.textContent = session.otpVerified ? "Used" : session.otp;
  renderTelemetry(session);

  if (!session.otpVerified) {
    sessionStatus.textContent = `${session.name} signed in as ${session.role}, waiting for OTP verification.`;
    clearRoleSections();
    resetAdminMonitor();
    renderWorkspace(state);
    return;
  }

  sessionStatus.textContent = `${session.name} is verified and active in the ${session.role} section.`;
  renderWorkspace(state);
}

function runSimulation(type) {
  const state = readState();
  const definitions = {
    bruteForce: {
      severity: "danger",
      title: "Brute-force campaign detected",
      description: "Multiple failed credential attempts triggered a rate-limit response and forced step-up verification.",
      blocked: true
    },
    tokenTheft: {
      severity: "danger",
      title: "Potential token theft blocked",
      description: "Session replay attempt was denied after policy mismatch between identity and device context.",
      blocked: true
    },
    unknownLocation: {
      severity: "warning",
      title: "Unknown location triggered re-authentication",
      description: "Policy engine downgraded trust and required additional verification for anomalous context.",
      blocked: false
    }
  };

  const incident = definitions[type];
  recordIncident(state, { type, ...incident });
  writeState(state);
  simMessage.textContent = incident.title;
  renderSession();
}

loginForm.addEventListener("submit", (event) => {
  event.preventDefault();
  loginMessage.textContent = "";
  otpMessage.textContent = "";

  const formData = new FormData(loginForm);
  const payload = Object.fromEntries(formData.entries());
  const user = users[payload.username];

  if (!user || user.password !== payload.password) {
    loginMessage.textContent = "Invalid credentials.";
    return;
  }

  const state = readState();
  const session = buildSession(user, state.session && state.session.username === user.username ? state.session : null);
  getUserStore(state, session.username);
  state.session = session;
  recordEvent(state, session, "login-issued");
  writeState(state);

  loginMessage.textContent = `Login accepted. Verify the fresh OTP to continue. Signed in as ${session.role}.`;
  setWorkspaceView("overview");
  renderSession();
});

otpForm.addEventListener("submit", (event) => {
  event.preventDefault();
  otpMessage.textContent = "";

  const state = readState();
  const session = state.session;
  const otpInput = document.getElementById("otp-input");

  if (!session) {
    otpMessage.textContent = "Sign in first.";
    return;
  }

  if (otpInput.value !== session.otp) {
    otpMessage.textContent = "Incorrect OTP.";
    return;
  }

  session.otpVerified = true;
  session.otp = null;
  session.lastSeenAt = nowIso();
  state.session = session;
  recordEvent(state, session, "otp-verified");
  writeState(state);

  otpMessage.textContent = "OTP verified. Access granted by role.";
  otpInput.value = "";
  setWorkspaceView("overview");
  renderSession();
});

regenerateBtn.addEventListener("click", () => {
  otpMessage.textContent = "";
  const state = readState();
  const session = state.session;

  if (!session) {
    otpMessage.textContent = "Sign in first.";
    return;
  }

  session.otp = generateOtp(session.otp);
  session.otpVerified = false;
  session.otpIssuedAt = nowIso();
  session.lastSeenAt = session.otpIssuedAt;
  session.otpUsageCount += 1;
  state.session = session;
  writeState(state);

  otpMessage.textContent = `A different OTP has been generated. Request count: ${session.otpUsageCount}.`;
  renderSession();
});

logoutBtn.addEventListener("click", () => {
  const state = readState();
  if (state.session) {
    const userStore = getUserStore(state, state.session.username);
    userStore.vaultUnlocked = false;
  }
  state.session = null;
  writeState(state);
  loginMessage.textContent = "";
  otpMessage.textContent = "";
  vaultSetMessage.textContent = "";
  vaultUnlockMessage.textContent = "";
  documentMessage.textContent = "";
  setWorkspaceView("overview");
  renderSession();
});

simulateBruteforceBtn.addEventListener("click", () => {
  runSimulation("bruteForce");
});

simulateTokenTheftBtn.addEventListener("click", () => {
  runSimulation("tokenTheft");
});

simulateLocationBtn.addEventListener("click", () => {
  runSimulation("unknownLocation");
});

clearIncidentsBtn.addEventListener("click", () => {
  const state = readState();
  state.incidents = [];
  writeState(state);
  simMessage.textContent = "Attack simulations cleared.";
  renderSession();
});

workspaceNavButtons.forEach((button) => {
  button.addEventListener("click", () => {
    if (button.classList.contains("hidden")) {
      return;
    }
    setWorkspaceView(button.dataset.view);
  });
});

vaultSetForm.addEventListener("submit", (event) => {
  event.preventDefault();
  vaultSetMessage.textContent = "";
  const state = readState();
  const session = state.session;

  if (!session || !session.otpVerified) {
    vaultSetMessage.textContent = "Verify a session first.";
    return;
  }

  const keyValue = document.getElementById("vault-key-input").value.trim();
  if (!keyValue) {
    vaultSetMessage.textContent = "Enter a private key.";
    return;
  }

  const userStore = getUserStore(state, session.username);
  userStore.vaultKey = keyValue;
  userStore.vaultUnlocked = false;
  writeState(state);

  vaultSetMessage.textContent = "Vault key saved for this user in browser storage.";
  vaultUnlockMessage.textContent = "";
  vaultSetForm.reset();
  renderSession();
});

vaultUnlockForm.addEventListener("submit", (event) => {
  event.preventDefault();
  vaultUnlockMessage.textContent = "";
  const state = readState();
  const session = state.session;

  if (!session || !session.otpVerified) {
    vaultUnlockMessage.textContent = "Verify a session first.";
    return;
  }

  const userStore = getUserStore(state, session.username);
  if (!userStore.vaultKey) {
    vaultUnlockMessage.textContent = "Set a vault key before unlocking.";
    return;
  }

  const unlockValue = document.getElementById("vault-unlock-input").value;
  if (unlockValue !== userStore.vaultKey) {
    userStore.vaultUnlocked = false;
    writeState(state);
    vaultUnlockMessage.textContent = "Incorrect vault key.";
    renderSession();
    return;
  }

  userStore.vaultUnlocked = true;
  writeState(state);
  vaultUnlockMessage.textContent = "Vault unlocked successfully.";
  vaultUnlockForm.reset();
  renderSession();
});

vaultLockBtn.addEventListener("click", () => {
  const state = readState();
  const session = state.session;
  if (!session || !session.otpVerified) {
    vaultUnlockMessage.textContent = "Verify a session first.";
    return;
  }

  const userStore = getUserStore(state, session.username);
  userStore.vaultUnlocked = false;
  writeState(state);
  vaultUnlockMessage.textContent = "Vault locked.";
  renderSession();
});

documentForm.addEventListener("submit", (event) => {
  event.preventDefault();
  documentMessage.textContent = "";
  const state = readState();
  const session = state.session;

  if (!session || !session.otpVerified) {
    documentMessage.textContent = "Verify a session first.";
    return;
  }

  if (session.role === "guest") {
    documentMessage.textContent = "Guests cannot upload documents in this workspace.";
    return;
  }

  const file = documentInput.files && documentInput.files[0];
  if (!file) {
    documentMessage.textContent = "Choose a file to add.";
    return;
  }

  const userStore = getUserStore(state, session.username);
  userStore.documents.unshift({
    fileName: file.name,
    fileSize: `${Math.max(1, Math.round(file.size / 1024))} KB`,
    note: documentNote.value.trim(),
    uploadedAt: nowIso(),
    ownerRole: session.role
  });
  userStore.documents = userStore.documents.slice(0, 12);
  writeState(state);

  documentMessage.textContent = `${file.name} added to the document hub.`;
  documentForm.reset();
  renderSession();
});

window.addEventListener("mousemove", (event) => {
  if (!cursorGlow) {
    return;
  }

  cursorGlow.style.opacity = "1";
  cursorGlow.style.left = `${event.clientX}px`;
  cursorGlow.style.top = `${event.clientY}px`;
});

window.addEventListener("mouseleave", () => {
  if (cursorGlow) {
    cursorGlow.style.opacity = "0";
  }
});

window.addEventListener("storage", () => {
  renderSession();
});

renderSession();
