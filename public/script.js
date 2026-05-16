const STORAGE_KEY = "secureu-student-safety-platform";

const users = {
  admin: { username: "admin", password: "Admin@123", role: "admin", name: "Campus Admin" },
  employee: { username: "employee", password: "Employee@123", role: "student", name: "Student Member" },
  guest: { username: "guest", password: "Guest@123", role: "guest", name: "Guest Visitor" }
};

const roleContent = {
  admin: [
    "Review overall student activity and suspicious behavior trends",
    "See how guests and students are using the security tools",
    "Monitor awareness progress and repeat-risk patterns"
  ],
  student: [
    "Use link scanning before applying to internships or contests",
    "Check passwords and improve security habits with plain-language guidance",
    "Practice awareness challenges and increase your safety score"
  ],
  guest: [
    "Explore safe browsing and scam awareness basics",
    "Run beginner checks without access to admin-only monitoring",
    "Receive limited guidance in a least-privilege environment"
  ]
};

const phishingKeywords = ["login", "verify", "urgent", "gift", "claim", "bonus", "wallet", "bank", "scholarship", "internship"];
const suspiciousTlds = [".xyz", ".top", ".click", ".live", ".info"];
const shorteners = ["bit.ly", "tinyurl.com", "t.co", "rb.gy", "goo.gl"];
const commonPasswordBits = ["password", "qwerty", "123456", "admin", "student", "welcome"];
const scamSignals = [
  { pattern: /urgent|immediately|right now|asap/i, reason: "The message uses urgency to push a quick decision.", weight: 22 },
  { pattern: /otp|verification code|one-time password/i, reason: "It asks for an OTP or verification code, which should never be shared.", weight: 35 },
  { pattern: /gift card|payment|transfer|send money|processing fee/i, reason: "It requests money or payment in a suspicious way.", weight: 30 },
  { pattern: /click here|open this link|download now/i, reason: "It pushes you toward a link or download without context.", weight: 18 },
  { pattern: /congratulations|selected|final chance|limited offer/i, reason: "It uses bait language to trigger excitement or fear of missing out.", weight: 16 },
  { pattern: /password|bank|account suspended|kyc/i, reason: "It asks for sensitive account details or identity confirmation.", weight: 28 }
];

const challengeButtons = Array.from(document.querySelectorAll(".challenge-btn"));
const workspaceNavButtons = Array.from(document.querySelectorAll(".workspace-nav-btn"));
const workspaceViews = Array.from(document.querySelectorAll(".workspace-view"));
const adminOnlyButtons = Array.from(document.querySelectorAll(".admin-only"));

const loginForm = document.getElementById("login-form");
const otpForm = document.getElementById("otp-form");
const regenerateBtn = document.getElementById("regenerate-btn");
const logoutBtn = document.getElementById("logout-btn");
const linkForm = document.getElementById("link-form");
const passwordForm = document.getElementById("password-form");
const scamForm = document.getElementById("scam-form");
const generatePassphraseBtn = document.getElementById("generate-passphrase-btn");

const loginMessage = document.getElementById("login-message");
const otpMessage = document.getElementById("otp-message");
const linkMessage = document.getElementById("link-message");
const passwordMessage = document.getElementById("password-message");
const scamMessage = document.getElementById("scam-message");
const challengeFeedback = document.getElementById("challenge-feedback");

const otpDisplayValue = document.getElementById("otp-display-value");
const sessionStatus = document.getElementById("session-status");
const trustScore = document.getElementById("trust-score");
const trustStatus = document.getElementById("trust-status");
const trustReasons = document.getElementById("trust-reasons");
const networkZone = document.getElementById("network-zone");
const browserName = document.getElementById("browser-name");
const osName = document.getElementById("os-name");
const deviceType = document.getElementById("device-type");
const ipAddress = document.getElementById("ip-address");
const policyDecision = document.getElementById("policy-decision");
const sessionCreated = document.getElementById("session-created");
const lastSeen = document.getElementById("last-seen");
const otpUsage = document.getElementById("otp-usage");

const workspaceRoot = document.getElementById("app-workspace");
const workspaceUserName = document.getElementById("workspace-user-name");
const workspaceUserRole = document.getElementById("workspace-user-role");
const workspaceSecurityScore = document.getElementById("workspace-security-score");
const workspaceScoreSummary = document.getElementById("workspace-score-summary");
const workspaceTitle = document.getElementById("workspace-title");
const workspaceSubtitle = document.getElementById("workspace-subtitle");
const heroSecurityScore = document.getElementById("hero-security-score");
const accountName = document.getElementById("account-name");
const accountRole = document.getElementById("account-role");
const challengeProgress = document.getElementById("challenge-progress");
const badgeCount = document.getElementById("badge-count");

const lastLinkStatus = document.getElementById("last-link-status");
const lastPasswordStatus = document.getElementById("last-password-status");
const lastScamStatus = document.getElementById("last-scam-status");

const linkRiskLabel = document.getElementById("link-risk-label");
const linkRiskScore = document.getElementById("link-risk-score");
const linkReasons = document.getElementById("link-reasons");

const passwordRiskLabel = document.getElementById("password-risk-label");
const passwordRiskScore = document.getElementById("password-risk-score");
const passwordReasons = document.getElementById("password-reasons");
const generatedPassphrase = document.getElementById("generated-passphrase");

const scamRiskLabel = document.getElementById("scam-risk-label");
const scamRiskScore = document.getElementById("scam-risk-score");
const scamReasons = document.getElementById("scam-reasons");

const deviceScoreLabel = document.getElementById("device-score-label");
const deviceRiskScore = document.getElementById("device-risk-score");
const deviceRecommendations = document.getElementById("device-recommendations");

const adminActivityList = document.getElementById("admin-activity-list");

const sections = {
  admin: document.getElementById("admin-section"),
  student: document.getElementById("employee-section"),
  guest: document.getElementById("guest-section")
};

const sectionLists = {
  admin: document.getElementById("admin-list"),
  student: document.getElementById("employee-list"),
  guest: document.getElementById("guest-list")
};

let activeView = "dashboard";

function defaultState() {
  return {
    session: null,
    events: [],
    challengeSolved: false,
    toolHistory: {
      link: null,
      password: null,
      scam: null
    }
  };
}

function readState() {
  try {
    const parsed = JSON.parse(localStorage.getItem(STORAGE_KEY));
    return {
      ...defaultState(),
      ...parsed,
      toolHistory: { ...defaultState().toolHistory, ...(parsed?.toolHistory || {}) },
      events: Array.isArray(parsed?.events) ? parsed.events : []
    };
  } catch {
    return defaultState();
  }
}

function writeState(state) {
  localStorage.setItem(STORAGE_KEY, JSON.stringify(state));
}

function nowIso() {
  return new Date().toISOString();
}

function formatTimestamp(value) {
  if (!value) {
    return "Pending";
  }
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? value : date.toLocaleString();
}

function summarizeOS(agent) {
  const ua = agent.toLowerCase();
  if (ua.includes("windows")) return "Windows";
  if (ua.includes("mac os") || ua.includes("macintosh")) return "macOS";
  if (ua.includes("android")) return "Android";
  if (ua.includes("iphone") || ua.includes("ipad")) return "iOS";
  if (ua.includes("linux")) return "Linux";
  return "Unknown OS";
}

function summarizeBrowser(agent) {
  const ua = agent.toLowerCase();
  if (ua.includes("edg/")) return "Microsoft Edge";
  if (ua.includes("chrome/") && !ua.includes("edg/")) return "Google Chrome";
  if (ua.includes("firefox/")) return "Mozilla Firefox";
  if (ua.includes("safari/") && !ua.includes("chrome/")) return "Safari";
  return "Unknown Browser";
}

function summarizeDevice(agent) {
  const ua = agent.toLowerCase();
  if (ua.includes("ipad") || ua.includes("tablet")) return "Tablet";
  if (ua.includes("mobile") || ua.includes("android") || ua.includes("iphone")) return "Mobile";
  return "Desktop";
}

function generateOtp(previousOtp) {
  let otp = "";
  do {
    otp = `${Math.floor(100000 + Math.random() * 900000)}`;
  } while (otp === previousOtp);
  return otp;
}

function buildTrustContext(role) {
  const userAgent = navigator.userAgent || "Unknown Agent";
  const browser = summarizeBrowser(userAgent);
  const os = summarizeOS(userAgent);
  const device = summarizeDevice(userAgent);

  let score = 68;
  const reasons = [
    "This demo uses browser, device type, and role to estimate a simple trust score.",
    "Verified sessions are treated more safely than anonymous visitors."
  ];

  if (device === "Desktop") {
    score += 8;
    reasons.push("Desktop sessions are treated as slightly lower risk for study and work tasks.");
  } else {
    score -= 4;
    reasons.push("Mobile access is convenient but needs more caution for sensitive actions.");
  }

  if (role === "admin") {
    score -= 6;
    reasons.push("Admin-level visibility requires stronger verification and closer monitoring.");
  } else if (role === "student") {
    score += 4;
    reasons.push("Student mode unlocks practical tools with limited platform risk.");
  } else {
    score -= 8;
    reasons.push("Guest sessions stay in a limited-access path for safety.");
  }

  let status = "Guided Access";
  let decision = "Basic tools available with continued monitoring.";

  if (score >= 78) {
    status = "Trusted";
    decision = "Full role access available inside the student dashboard.";
  } else if (score < 62) {
    status = "Restricted";
    decision = "Only limited features should be used until trust improves.";
  }

  return {
    score: Math.max(0, Math.min(100, score)),
    status,
    decision,
    browser,
    os,
    device,
    networkZone: "Public Web Session",
    ipAddress: "Browser-side demo context",
    reasons
  };
}

function buildSession(user, previousSession) {
  const createdAt = nowIso();
  return {
    username: user.username,
    name: user.name,
    role: user.role,
    otp: generateOtp(previousSession?.otp || null),
    otpVerified: false,
    createdAt,
    lastSeenAt: createdAt,
    otpUsageCount: previousSession ? previousSession.otpUsageCount + 1 : 1,
    trust: buildTrustContext(user.role)
  };
}

function recordEvent(state, session, type) {
  state.events.unshift({
    timestamp: nowIso(),
    type,
    username: session.username,
    name: session.name,
    role: session.role,
    trustScore: session.trust.score,
    browser: session.trust.browser,
    device: session.trust.device
  });
  state.events = state.events.slice(0, 20);
}

function setView(name) {
  activeView = name;
  workspaceNavButtons.forEach((button) => {
    button.classList.toggle("active", button.dataset.view === name);
  });
  workspaceViews.forEach((panel) => {
    panel.classList.toggle("active", panel.dataset.viewPanel === name);
  });
}

function resetRoleSections() {
  Object.values(sections).forEach((section) => section.classList.add("hidden"));
  Object.values(sectionLists).forEach((list) => {
    list.innerHTML = "";
  });
}

function renderRoleSections(role) {
  resetRoleSections();
  const visible = role === "admin" ? ["admin", "student", "guest"] : [role];
  visible.forEach((roleKey) => {
    const section = sections[roleKey];
    const list = sectionLists[roleKey];
    if (!section || !list) return;
    roleContent[roleKey].forEach((item) => {
      const li = document.createElement("li");
      li.textContent = item;
      list.appendChild(li);
    });
    section.classList.remove("hidden");
  });
}

function renderAdminMonitor(events) {
  const visibleEvents = events.filter((event) => event.role !== "admin");
  if (!visibleEvents.length) {
    adminActivityList.innerHTML = `
      <article class="activity-card empty-state">
        <h4>No activity yet</h4>
        <p>Recent student and guest login events will appear here for the admin.</p>
      </article>
    `;
    return;
  }

  adminActivityList.innerHTML = "";
  visibleEvents.forEach((event) => {
    const card = document.createElement("article");
    card.className = "activity-card";
    card.innerHTML = `
      <h4>${event.name}</h4>
      <p>${event.role} completed ${event.type === "otp-verified" ? "OTP verification" : "login initiation"}.</p>
      <p>${formatTimestamp(event.timestamp)} | ${event.browser} | ${event.device} | Trust ${event.trustScore}/100</p>
    `;
    adminActivityList.appendChild(card);
  });
}

function updateList(target, items) {
  target.innerHTML = "";
  items.forEach((item) => {
    const li = document.createElement("li");
    li.textContent = item;
    target.appendChild(li);
  });
}

function scoreSummary(score) {
  if (score >= 85) return "Excellent. You are following strong personal security habits.";
  if (score >= 70) return "Good. A few improvements can make your digital routine much safer.";
  if (score >= 55) return "Fair. You are protected in some areas, but you still have clear weak points.";
  return "Needs attention. Review passwords, suspicious messages, and browsing habits soon.";
}

function calculateWorkspaceScore(state) {
  const session = state.session;
  if (!session || !session.otpVerified) {
    return 0;
  }

  let score = session.trust.score;
  if (state.toolHistory.link?.score <= 35) score += 4;
  if (state.toolHistory.password?.score >= 75) score += 6;
  if (state.toolHistory.scam?.score <= 30) score += 4;
  if (state.challengeSolved) score += 8;
  return Math.max(0, Math.min(100, score));
}

function renderDashboard(state) {
  const session = state.session;
  if (!session || !session.otpVerified) {
    workspaceRoot.classList.add("hidden");
    workspaceUserName.textContent = "No active user";
    workspaceUserRole.textContent = "Login required";
    workspaceSecurityScore.textContent = "0";
    workspaceScoreSummary.textContent = "Login to generate your safety overview.";
    sessionStatus.textContent = "No verified user yet.";
    trustScore.textContent = "Pending";
    trustStatus.textContent = "Pending";
    accountName.textContent = "Pending";
    accountRole.textContent = "Pending";
    networkZone.textContent = "Pending";
    browserName.textContent = "Pending";
    osName.textContent = "Pending";
    deviceType.textContent = "Pending";
    ipAddress.textContent = "Pending";
    policyDecision.textContent = "Pending";
    sessionCreated.textContent = "Pending";
    lastSeen.textContent = "Pending";
    otpUsage.textContent = "0";
    challengeProgress.textContent = state.challengeSolved ? "1/3" : "0/3";
    badgeCount.textContent = state.challengeSolved ? "1 badge earned" : "0 badges earned";
    updateList(trustReasons, ["Login and verify OTP to see personalized security guidance."]);
    resetRoleSections();
    return;
  }

  workspaceRoot.classList.remove("hidden");
  workspaceUserName.textContent = session.name;
  workspaceUserRole.textContent = `${session.role.toUpperCase()} access`;
  workspaceTitle.textContent = `Welcome back, ${session.name}`;
  workspaceSubtitle.textContent = "Use these practical security tools to make safer decisions online.";

  const overallScore = calculateWorkspaceScore(state);
  workspaceSecurityScore.textContent = String(overallScore);
  workspaceScoreSummary.textContent = scoreSummary(overallScore);
  heroSecurityScore.textContent = String(Math.max(78, overallScore));

  sessionStatus.textContent = `${session.name} is verified and can use the SecureU dashboard.`;
  trustScore.textContent = `${session.trust.score}/100`;
  trustStatus.textContent = session.trust.status;
  accountName.textContent = session.name;
  accountRole.textContent = session.role;
  networkZone.textContent = session.trust.networkZone;
  browserName.textContent = session.trust.browser;
  osName.textContent = session.trust.os;
  deviceType.textContent = session.trust.device;
  ipAddress.textContent = session.trust.ipAddress;
  policyDecision.textContent = session.trust.decision;
  sessionCreated.textContent = formatTimestamp(session.createdAt);
  lastSeen.textContent = formatTimestamp(session.lastSeenAt);
  otpUsage.textContent = String(session.otpUsageCount);
  challengeProgress.textContent = state.challengeSolved ? "1/3" : "0/3";
  badgeCount.textContent = state.challengeSolved ? "1 badge earned" : "0 badges earned";

  const dynamicAdvice = [...session.trust.reasons];
  if (!state.toolHistory.link) dynamicAdvice.push("Use the link scanner before opening internship, scholarship, or payment URLs.");
  if (!state.toolHistory.password) dynamicAdvice.push("Run a password check to understand whether your current passwords are too easy to crack.");
  if (!state.toolHistory.scam) dynamicAdvice.push("Paste a suspicious message into the scam detector before replying or clicking.");
  updateList(trustReasons, dynamicAdvice);

  lastLinkStatus.textContent = state.toolHistory.link ? `${state.toolHistory.link.label} (${state.toolHistory.link.score}/100)` : "Not scanned yet";
  lastPasswordStatus.textContent = state.toolHistory.password
    ? `${state.toolHistory.password.label} (${state.toolHistory.password.score}/100)`
    : "Not checked yet";
  lastScamStatus.textContent = state.toolHistory.scam ? `${state.toolHistory.scam.label} (${state.toolHistory.scam.score}/100)` : "Not analyzed yet";

  renderRoleSections(session.role);
  const showAdmin = session.role === "admin";
  adminOnlyButtons.forEach((button) => button.classList.toggle("hidden", !showAdmin));
  if (showAdmin) {
    renderAdminMonitor(state.events);
  } else if (activeView === "monitor") {
    setView("dashboard");
  }

  renderDeviceCheckup(session, state);
}

function analyzeLink(url) {
  let risk = 8;
  const reasons = [];
  let host = "";

  try {
    const parsed = new URL(url);
    host = parsed.hostname.toLowerCase();

    if (parsed.protocol !== "https:") {
      risk += 24;
      reasons.push("This link is not using HTTPS, so it should be treated more carefully.");
    } else {
      reasons.push("The link uses HTTPS, which is a positive sign but not a full guarantee.");
    }

    if (shorteners.some((domain) => host.includes(domain))) {
      risk += 18;
      reasons.push("The domain looks like a URL shortener, which can hide the real destination.");
    }

    if (suspiciousTlds.some((tld) => host.endsWith(tld))) {
      risk += 16;
      reasons.push("The website uses a TLD that often appears in low-trust campaigns.");
    }

    if (/\d+\.\d+\.\d+\.\d+/.test(host)) {
      risk += 26;
      reasons.push("The link uses a raw IP address instead of a normal domain name.");
    }

    if (host.split("-").length > 3) {
      risk += 12;
      reasons.push("The domain has many hyphens, which can be a sign of a fake or rushed site.");
    }

    if (host.includes("xn--")) {
      risk += 24;
      reasons.push("The domain uses punycode characters, which can be used in lookalike attacks.");
    }

    if (phishingKeywords.some((word) => url.toLowerCase().includes(word))) {
      risk += 14;
      reasons.push("The URL includes bait terms often used in phishing or scam pages.");
    }

    if (url.length > 90) {
      risk += 10;
      reasons.push("The link is unusually long, which can hide suspicious paths or parameters.");
    }
  } catch {
    return {
      label: "Dangerous",
      score: 95,
      reasons: ["The text is not a valid URL, so you should not trust or open it."]
    };
  }

  risk = Math.max(0, Math.min(100, risk));
  let label = "Safe";
  if (risk >= 65) label = "Dangerous";
  else if (risk >= 35) label = "Suspicious";

  if (!reasons.length) {
    reasons.push("No obvious warning signs were found in this URL pattern.");
  }

  return { label, score: risk, reasons, host };
}

function analyzePassword(value) {
  let score = 10;
  const reasons = [];

  if (value.length >= 14) {
    score += 35;
    reasons.push("Good length makes the password much harder to crack.");
  } else if (value.length >= 10) {
    score += 20;
    reasons.push("The length is decent, but a longer passphrase would be safer.");
  } else {
    reasons.push("This password is too short and should be replaced with something longer.");
  }

  if (/[A-Z]/.test(value) && /[a-z]/.test(value)) {
    score += 12;
    reasons.push("Mixing uppercase and lowercase letters improves variety.");
  }

  if (/\d/.test(value)) {
    score += 10;
    reasons.push("Adding numbers helps resist simple guessing.");
  }

  if (/[^a-zA-Z0-9]/.test(value)) {
    score += 12;
    reasons.push("Special characters increase the search space for attackers.");
  }

  if (commonPasswordBits.some((part) => value.toLowerCase().includes(part))) {
    score -= 28;
    reasons.push("It includes a very common password pattern or predictable word.");
  }

  if (/(.)\1{2,}/.test(value)) {
    score -= 10;
    reasons.push("Repeated characters make the pattern easier to guess.");
  }

  if (/^\d+$/.test(value)) {
    score -= 20;
    reasons.push("All-number passwords are weak and should be avoided.");
  }

  score = Math.max(0, Math.min(100, score));
  let label = "Weak";
  if (score >= 75) label = "Strong";
  else if (score >= 45) label = "Okay";

  return { label, score, reasons };
}

function analyzeScam(text) {
  let risk = 8;
  const reasons = [];
  scamSignals.forEach((signal) => {
    if (signal.pattern.test(text)) {
      risk += signal.weight;
      reasons.push(signal.reason);
    }
  });

  if (/(gmail\.com|yahoo\.com|outlook\.com)/i.test(text) && /company|official|hr team/i.test(text)) {
    risk += 12;
    reasons.push("The message claims authority but may be relying on a generic email context.");
  }

  if (text.length < 25) {
    risk += 6;
    reasons.push("Very short messages can hide context and encourage impulsive clicks.");
  }

  risk = Math.max(0, Math.min(100, risk));
  let label = "Likely Safe";
  if (risk >= 70) label = "High Scam Risk";
  else if (risk >= 40) label = "Suspicious";

  if (!reasons.length) {
    reasons.push("No major scam language was detected in this message sample.");
  }

  return { label, score: risk, reasons };
}

function generatePassphrase() {
  const wordsA = ["campus", "shield", "quiet", "orbit", "river", "signal", "cobalt", "sunrise"];
  const wordsB = ["panda", "harbor", "ember", "matrix", "window", "rocket", "garden", "cipher"];
  const wordsC = ["notes", "bridge", "planet", "studio", "marble", "forest", "anchor", "socket"];
  const number = Math.floor(100 + Math.random() * 900);
  return `${wordsA[Math.floor(Math.random() * wordsA.length)]}-${wordsB[Math.floor(Math.random() * wordsB.length)]}-${wordsC[Math.floor(Math.random() * wordsC.length)]}-${number}`;
}

function renderDeviceCheckup(session, state) {
  if (!session || !session.otpVerified) {
    deviceScoreLabel.textContent = "Waiting for session";
    deviceRiskScore.textContent = "Safety score: --";
    updateList(deviceRecommendations, ["Login to see beginner-friendly browser and device advice."]);
    return;
  }

  let score = session.trust.score;
  const advice = [];

  if (navigator.cookieEnabled) {
    advice.push("Cookies are enabled. Be careful on shared devices and log out after important sessions.");
  } else {
    score += 4;
    advice.push("Cookie restrictions are helping with privacy, but some sites may behave differently.");
  }

  if (navigator.doNotTrack === "1") {
    score += 4;
    advice.push("Do Not Track is enabled, which is a small privacy-positive signal.");
  } else {
    advice.push("Consider enabling privacy protections in your browser to reduce unnecessary tracking.");
  }

  if (window.isSecureContext) {
    score += 4;
    advice.push("This site is running in a secure browser context.");
  } else {
    score -= 8;
    advice.push("Avoid entering sensitive information on insecure browser contexts.");
  }

  if (!navigator.onLine) {
    score -= 10;
    advice.push("Your browser reports that you are offline, so some checks may not reflect your real environment.");
  } else {
    advice.push("You are online, so be extra careful on public Wi-Fi and shared networks.");
  }

  score = Math.max(0, Math.min(100, score));
  deviceScoreLabel.textContent = score >= 75 ? "Healthy Device Posture" : score >= 55 ? "Needs Small Improvements" : "Needs Attention";
  deviceRiskScore.textContent = `Safety score: ${score}/100`;
  updateList(deviceRecommendations, advice);
}

function renderToolResult(targetLabel, targetScore, targetReasons, result, prefix) {
  targetLabel.textContent = result.label;
  targetScore.textContent = `${prefix}: ${result.score}/100`;
  updateList(targetReasons, result.reasons);
}

loginForm.addEventListener("submit", (event) => {
  event.preventDefault();
  loginMessage.textContent = "";
  otpMessage.textContent = "";

  const data = new FormData(loginForm);
  const username = data.get("username");
  const password = data.get("password");
  const user = users[username];

  if (!user || user.password !== password) {
    loginMessage.textContent = "Invalid credentials.";
    return;
  }

  const state = readState();
  const previous = state.session && state.session.username === user.username ? state.session : null;
  state.session = buildSession(user, previous);
  recordEvent(state, state.session, "login-issued");
  writeState(state);

  otpDisplayValue.textContent = state.session.otp;
  loginMessage.textContent = `Login accepted. OTP generated for ${state.session.role}.`;
  setView("dashboard");
  renderDashboard(state);
});

otpForm.addEventListener("submit", (event) => {
  event.preventDefault();
  const state = readState();
  const session = state.session;
  otpMessage.textContent = "";

  if (!session) {
    otpMessage.textContent = "Sign in first.";
    return;
  }

  const otpInput = document.getElementById("otp-input").value;
  if (otpInput !== session.otp) {
    otpMessage.textContent = "Incorrect OTP.";
    return;
  }

  session.otpVerified = true;
  session.otp = null;
  session.lastSeenAt = nowIso();
  state.session = session;
  recordEvent(state, session, "otp-verified");
  writeState(state);

  otpDisplayValue.textContent = "Used";
  otpMessage.textContent = "OTP verified. Student dashboard unlocked.";
  otpForm.reset();
  setView("dashboard");
  renderDashboard(state);
});

regenerateBtn.addEventListener("click", () => {
  const state = readState();
  const session = state.session;
  otpMessage.textContent = "";

  if (!session) {
    otpMessage.textContent = "Sign in first.";
    return;
  }

  session.otp = generateOtp(session.otp);
  session.otpVerified = false;
  session.lastSeenAt = nowIso();
  session.otpUsageCount += 1;
  state.session = session;
  writeState(state);

  otpDisplayValue.textContent = session.otp;
  otpMessage.textContent = `A different OTP has been generated. Request count: ${session.otpUsageCount}.`;
  renderDashboard(state);
});

logoutBtn.addEventListener("click", () => {
  const state = readState();
  state.session = null;
  writeState(state);
  loginMessage.textContent = "";
  otpMessage.textContent = "";
  renderDashboard(state);
});

workspaceNavButtons.forEach((button) => {
  button.addEventListener("click", () => {
    if (button.classList.contains("hidden")) return;
    setView(button.dataset.view);
  });
});

linkForm.addEventListener("submit", (event) => {
  event.preventDefault();
  const state = readState();
  const value = document.getElementById("link-input").value.trim();
  const result = analyzeLink(value);
  state.toolHistory.link = result;
  writeState(state);

  renderToolResult(linkRiskLabel, linkRiskScore, linkReasons, result, "Risk score");
  lastLinkStatus.textContent = `${result.label} (${result.score}/100)`;
  linkMessage.textContent = `Scan complete for ${result.host || "the supplied link"}.`;
  renderDashboard(readState());
});

passwordForm.addEventListener("submit", (event) => {
  event.preventDefault();
  const state = readState();
  const value = document.getElementById("password-check-input").value;
  const result = analyzePassword(value);
  state.toolHistory.password = result;
  writeState(state);

  renderToolResult(passwordRiskLabel, passwordRiskScore, passwordReasons, result, "Strength score");
  lastPasswordStatus.textContent = `${result.label} (${result.score}/100)`;
  passwordMessage.textContent = "Password check completed.";
  renderDashboard(readState());
});

generatePassphraseBtn.addEventListener("click", () => {
  const passphrase = generatePassphrase();
  generatedPassphrase.textContent = passphrase;
  passwordMessage.textContent = "Passphrase generated. You can use it as inspiration for a safer login.";
});

scamForm.addEventListener("submit", (event) => {
  event.preventDefault();
  const state = readState();
  const value = document.getElementById("scam-input").value.trim();
  const result = analyzeScam(value);
  state.toolHistory.scam = result;
  writeState(state);

  renderToolResult(scamRiskLabel, scamRiskScore, scamReasons, result, "Scam probability");
  lastScamStatus.textContent = `${result.label} (${result.score}/100)`;
  scamMessage.textContent = "Message analysis completed.";
  renderDashboard(readState());
});

challengeButtons.forEach((button) => {
  button.addEventListener("click", () => {
    const correct = button.dataset.correct === "true";
    const state = readState();
    state.challengeSolved = correct;
    writeState(state);
    challengeFeedback.textContent = correct
      ? "Correct. OTPs should never be shared, even when a message looks official."
      : "Not quite. The safest move is to never share an OTP and verify the sender another way.";
    renderDashboard(readState());
  });
});

window.addEventListener("storage", () => {
  renderDashboard(readState());
});

setView("dashboard");
renderDashboard(readState());
