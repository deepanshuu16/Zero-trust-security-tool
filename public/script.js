const STORAGE_KEY = "secureu-zero-trust-platform";

const users = {
  admin: { username: "admin", password: "Admin@123", role: "admin", name: "Platform Administrator" },
  employee: { username: "employee", password: "Employee@123", role: "employee", name: "Operations Employee" },
  analyst: { username: "analyst", password: "Analyst@123", role: "analyst", name: "Security Analyst" },
  guest: { username: "guest", password: "Guest@123", role: "guest", name: "Guest Visitor" }
};

const roleContent = {
  admin: [
    "Full access to identity, monitoring, settings, and platform controls",
    "Can review users, devices, alerts, and audit logs across the platform",
    "Can adjust verification policies and continuous monitoring rules"
  ],
  employee: [
    "Limited access to security tools, personal score, and recommendations",
    "Can scan links, check passwords, review risk posture, and upload files",
    "Cannot access organization-wide monitoring or full audit controls"
  ],
  analyst: [
    "Monitoring-first access to threat feeds, live sessions, and audit logs",
    "Can review suspicious behavior, device trust, and platform alerts",
    "Cannot change platform-wide identity settings like a full admin"
  ],
  guest: [
    "Minimal access to awareness tools and limited guided protection flows",
    "Can review basic checks and educational content only",
    "Cannot access sensitive dashboards or organization-level telemetry"
  ]
};

const phishingKeywords = ["login", "verify", "urgent", "gift", "claim", "bonus", "bank", "scholarship", "internship", "wallet"];
const suspiciousTlds = [".xyz", ".click", ".top", ".live", ".info"];
const shorteners = ["bit.ly", "tinyurl.com", "t.co", "rb.gy", "goo.gl"];
const commonPasswordBits = ["password", "qwerty", "123456", "welcome", "admin", "student"];
const scamSignals = [
  { pattern: /urgent|immediately|asap|right now/i, reason: "The message uses urgency to force a quick decision.", weight: 20 },
  { pattern: /otp|verification code|one-time password/i, reason: "It asks for an OTP or verification code, which should never be shared.", weight: 35 },
  { pattern: /gift card|processing fee|payment|send money|transfer/i, reason: "It requests money or payment in a suspicious context.", weight: 28 },
  { pattern: /click here|download now|open this link/i, reason: "It pushes you toward a link or download without enough trust context.", weight: 16 },
  { pattern: /congratulations|selected|limited offer|final chance/i, reason: "It uses bait language to trigger emotional reactions.", weight: 14 },
  { pattern: /password|bank|kyc|account suspended/i, reason: "It asks for sensitive account information.", weight: 22 }
];

function defaultState() {
  return {
    session: null,
    events: [],
    logs: [],
    challengeSolved: false,
    failedAttempts: 0,
    settings: {
      emailOtp: true,
      phoneOtp: false,
      googleAuth: true,
      biometric: false,
      deviceFingerprinting: true,
      continuousAuth: true
    },
    toolHistory: {
      link: null,
      password: null,
      scam: null,
      file: null
    }
  };
}

function readState() {
  try {
    const parsed = JSON.parse(localStorage.getItem(STORAGE_KEY));
    return {
      ...defaultState(),
      ...parsed,
      settings: { ...defaultState().settings, ...(parsed?.settings || {}) },
      toolHistory: { ...defaultState().toolHistory, ...(parsed?.toolHistory || {}) },
      events: Array.isArray(parsed?.events) ? parsed.events : [],
      logs: Array.isArray(parsed?.logs) ? parsed.logs : []
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
  if (!value) return "Pending";
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

function stableNumber(input) {
  return Array.from(input).reduce((sum, char, index) => sum + char.charCodeAt(0) * (index + 1), 0);
}

function activeVerificationMethods(settings) {
  const methods = ["Password"];
  if (settings.emailOtp) methods.push("Email OTP");
  if (settings.phoneOtp) methods.push("Phone OTP");
  if (settings.googleAuth) methods.push("Google Auth");
  if (settings.biometric) methods.push("Biometric");
  if (settings.deviceFingerprinting) methods.push("Device Fingerprint");
  return methods;
}

function generateOtp(previousOtp) {
  let otp = "";
  do {
    otp = `${Math.floor(100000 + Math.random() * 900000)}`;
  } while (otp === previousOtp);
  return otp;
}

function analyzeRisk(role, state) {
  const userAgent = navigator.userAgent || "Unknown Agent";
  const browser = summarizeBrowser(userAgent);
  const os = summarizeOS(userAgent);
  const device = summarizeDevice(userAgent);
  const timezone = Intl.DateTimeFormat().resolvedOptions().timeZone || "Unknown timezone";
  const locale = navigator.language || "Unknown locale";
  const fingerprint = `FP-${stableNumber(`${userAgent}-${timezone}-${locale}`).toString(16).slice(0, 8).toUpperCase()}`;
  const signalSeed = stableNumber(`${role}-${timezone}-${locale}-${browser}-${device}`);

  const vpnDetected = signalSeed % 5 === 0;
  const suspiciousBrowserChange = signalSeed % 7 === 0;
  const impossibleTravel = signalSeed % 11 === 0 && state.failedAttempts > 0;
  const newDevice = signalSeed % 3 === 0;

  let riskScore = 22;
  const reasons = [
    "The platform continuously evaluates user identity, device context, and session behavior."
  ];

  if (device === "Desktop") {
    riskScore += 4;
    reasons.push("Desktop device profile is generally more stable for long work sessions.");
  } else {
    riskScore += 12;
    reasons.push("Mobile sessions are treated as slightly higher risk for sensitive actions.");
  }

  if (role === "admin") {
    riskScore += 18;
    reasons.push("Admin accounts require stricter monitoring because they hold wider access.");
  } else if (role === "analyst") {
    riskScore += 12;
    reasons.push("Analyst sessions have elevated visibility into monitoring data.");
  } else if (role === "guest") {
    riskScore += 16;
    reasons.push("Guest sessions stay restricted because identity assurance is weaker.");
  } else {
    riskScore += 8;
    reasons.push("Employee sessions receive standard policy checks with limited platform access.");
  }

  if (state.failedAttempts > 0) {
    riskScore += Math.min(16, state.failedAttempts * 4);
    reasons.push("Recent failed login attempts increase the session risk profile.");
  }

  if (vpnDetected) {
    riskScore += 10;
    reasons.push("The session appears to be using a VPN-like network pattern, so extra checks are recommended.");
  }

  if (suspiciousBrowserChange) {
    riskScore += 12;
    reasons.push("The browser fingerprint looks inconsistent with the baseline pattern.");
  }

  if (impossibleTravel) {
    riskScore += 18;
    reasons.push("The platform detected an impossible-travel style scenario in the simulated policy engine.");
  }

  if (newDevice) {
    riskScore += 8;
    reasons.push("This device appears new to the session history and needs trust validation.");
  }

  let riskLevel = "Low";
  if (riskScore >= 70) riskLevel = "High";
  else if (riskScore >= 45) riskLevel = "Medium";

  let threatLevel = "Guarded";
  if (riskLevel === "High") threatLevel = "Critical";
  else if (riskLevel === "Medium") threatLevel = "Elevated";

  let deviceTrust = "Trusted";
  if (riskLevel === "High") deviceTrust = "Dangerous";
  else if (riskLevel === "Medium" || newDevice) deviceTrust = "Unknown";

  let decision = "Access granted with active monitoring.";
  if (riskLevel === "High") {
    decision = "High-risk session. Force stronger verification and limit access surfaces.";
  } else if (riskLevel === "Medium") {
    decision = "Medium-risk session. Keep access monitored and require step-up verification for risky actions.";
  }

  return {
    browser,
    os,
    device,
    timezone,
    locale,
    fingerprint,
    vpnDetected,
    suspiciousBrowserChange,
    impossibleTravel,
    newDevice,
    riskScore,
    riskLevel,
    threatLevel,
    deviceTrust,
    decision,
    reasons
  };
}

function buildSession(user, previousSession, state) {
  const createdAt = nowIso();
  const risk = analyzeRisk(user.role, state);
  const methods = activeVerificationMethods(state.settings);
  const trustScore = Math.max(0, 100 - risk.riskScore + (methods.length - 1) * 2);

  return {
    username: user.username,
    name: user.name,
    role: user.role,
    otp: generateOtp(previousSession?.otp || null),
    otpVerified: false,
    createdAt,
    lastSeenAt: createdAt,
    otpUsageCount: previousSession ? previousSession.otpUsageCount + 1 : 1,
    nextReviewAt: new Date(Date.now() + 3 * 60 * 1000).toISOString(),
    trust: {
      score: Math.max(0, Math.min(100, trustScore)),
      status: risk.riskLevel === "High" ? "Restricted" : risk.riskLevel === "Medium" ? "Elevated Review" : "Trusted",
      decision: risk.decision,
      browser: risk.browser,
      os: risk.os,
      device: risk.device,
      networkZone: "Public Web Session",
      ipAddress: "Browser-side demo context",
      deviceFingerprint: risk.fingerprint,
      deviceTrust: risk.deviceTrust,
      riskLevel: risk.riskLevel,
      threatLevel: risk.threatLevel,
      verificationMethods: methods,
      vpnDetected: risk.vpnDetected,
      suspiciousBrowserChange: risk.suspiciousBrowserChange,
      impossibleTravel: risk.impossibleTravel,
      newDevice: risk.newDevice,
      timezone: risk.timezone,
      locale: risk.locale,
      reasons: risk.reasons
    }
  };
}

function recordEvent(state, session, type, detail) {
  state.events.unshift({
    timestamp: nowIso(),
    type,
    detail,
    username: session.username,
    name: session.name,
    role: session.role,
    trustScore: session.trust.score,
    browser: session.trust.browser,
    device: session.trust.device
  });
  state.events = state.events.slice(0, 40);
}

function recordLog(state, level, title, detail, category = "monitoring") {
  state.logs.unshift({
    timestamp: nowIso(),
    level,
    title,
    detail,
    category
  });
  state.logs = state.logs.slice(0, 80);
}

function seedLogs(state) {
  if (state.logs.length) return;
  recordLog(state, "info", "Platform ready", "Zero Trust monitoring engine is active in demo mode.", "system");
  recordLog(state, "success", "Policy baseline loaded", "Default verification methods and risk policies are available.", "policy");
}

function ensureContinuousReview(state) {
  if (!state.session || !state.session.otpVerified || !state.settings.continuousAuth) return;

  const now = Date.now();
  const nextReviewAt = new Date(state.session.nextReviewAt || 0).getTime();
  if (Number.isNaN(nextReviewAt) || now < nextReviewAt) return;

  const user = Object.values(users).find((item) => item.username === state.session.username);
  if (!user) return;

  const previousScore = state.session.trust.score;
  const refreshed = buildSession(user, state.session, state);
  refreshed.otpVerified = state.session.otpVerified;
  refreshed.otp = null;
  refreshed.createdAt = state.session.createdAt;
  refreshed.lastSeenAt = nowIso();
  state.session = refreshed;

  if (refreshed.trust.riskLevel === "High") {
    recordLog(state, "warning", "Continuous re-check raised risk", "Session moved into high-risk mode and would require step-up verification.", "session");
  } else {
    recordLog(state, "info", "Continuous re-check completed", `Trust score moved from ${previousScore} to ${refreshed.trust.score}.`, "session");
  }
}

function scoreSummary(score) {
  if (score >= 85) return "Excellent. Identity, device trust, and monitoring signals are strong.";
  if (score >= 70) return "Good. The session is healthy, but a few extra protections would help.";
  if (score >= 55) return "Fair. Some controls are active, but risk remains visible.";
  return "Needs attention. This session would need stronger verification and tighter policy control.";
}

function calculateOverallScore(state) {
  const session = state.session;
  if (!session || !session.otpVerified) return 0;
  let score = session.trust.score;
  if (state.toolHistory.link && state.toolHistory.link.score <= 35) score += 3;
  if (state.toolHistory.password && state.toolHistory.password.score >= 75) score += 5;
  if (state.toolHistory.scam && state.toolHistory.scam.score <= 30) score += 3;
  if (state.toolHistory.file && state.toolHistory.file.label === "Clean") score += 3;
  if (state.challengeSolved) score += 6;
  return Math.max(0, Math.min(100, score));
}

function updateList(target, items) {
  if (!target) return;
  target.innerHTML = "";
  items.forEach((item) => {
    const li = document.createElement("li");
    li.textContent = item;
    target.appendChild(li);
  });
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
      reasons.push("The link is not using HTTPS, so it should be treated more carefully.");
    } else {
      reasons.push("The link uses HTTPS, which is a positive sign but not a guarantee.");
    }

    if (shorteners.some((domain) => host.includes(domain))) {
      risk += 18;
      reasons.push("This looks like a shortened URL that hides the final destination.");
    }

    if (suspiciousTlds.some((tld) => host.endsWith(tld))) {
      risk += 16;
      reasons.push("The domain ending appears in many low-trust or disposable websites.");
    }

    if (/\d+\.\d+\.\d+\.\d+/.test(host)) {
      risk += 24;
      reasons.push("The URL uses a raw IP address instead of a familiar domain name.");
    }

    if (host.split("-").length > 3) {
      risk += 10;
      reasons.push("The domain has many hyphens, which can be a sign of a fake site.");
    }

    if (host.includes("xn--")) {
      risk += 22;
      reasons.push("The domain uses punycode characters that can be used in lookalike attacks.");
    }

    if (phishingKeywords.some((word) => url.toLowerCase().includes(word))) {
      risk += 14;
      reasons.push("The URL contains bait words often seen in scam or phishing campaigns.");
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
  if (!reasons.length) reasons.push("No obvious warning signs were found in this URL.");
  return { label, score: risk, reasons, host };
}

function analyzePassword(value) {
  let score = 10;
  const reasons = [];

  if (value.length >= 14) {
    score += 35;
    reasons.push("The length is strong and helps resist cracking.");
  } else if (value.length >= 10) {
    score += 20;
    reasons.push("The length is decent, but a longer passphrase would be safer.");
  } else {
    reasons.push("This password is short and should be replaced.");
  }

  if (/[A-Z]/.test(value) && /[a-z]/.test(value)) {
    score += 12;
    reasons.push("Mixing uppercase and lowercase letters improves variety.");
  }

  if (/\d/.test(value)) {
    score += 10;
    reasons.push("Numbers make simple guessing harder.");
  }

  if (/[^a-zA-Z0-9]/.test(value)) {
    score += 12;
    reasons.push("Special characters add useful complexity.");
  }

  if (commonPasswordBits.some((part) => value.toLowerCase().includes(part))) {
    score -= 28;
    reasons.push("It contains a very common password word or pattern.");
  }

  if (/^\d+$/.test(value)) {
    score -= 20;
    reasons.push("All-number passwords are weak and predictable.");
  }

  if (/(.)\1{2,}/.test(value)) {
    score -= 10;
    reasons.push("Repeated characters make the password easier to guess.");
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

  if (/(gmail\.com|yahoo\.com|outlook\.com)/i.test(text) && /official|company|hr/i.test(text)) {
    risk += 12;
    reasons.push("The message claims authority but relies on a generic email context.");
  }

  if (text.length < 25) {
    risk += 6;
    reasons.push("Very short messages can hide context and push impulsive actions.");
  }

  risk = Math.max(0, Math.min(100, risk));
  let label = "Likely Safe";
  if (risk >= 70) label = "High Scam Risk";
  else if (risk >= 40) label = "Suspicious";
  if (!reasons.length) reasons.push("No major scam language was detected in this message sample.");
  return { label, score: risk, reasons };
}

function generatePassphrase() {
  const wordsA = ["campus", "shield", "quiet", "orbit", "river", "signal", "cobalt", "sunrise"];
  const wordsB = ["panda", "harbor", "ember", "matrix", "window", "garden", "cipher", "anchor"];
  const wordsC = ["notes", "bridge", "planet", "studio", "marble", "forest", "socket", "lantern"];
  const number = Math.floor(100 + Math.random() * 900);
  return `${wordsA[Math.floor(Math.random() * wordsA.length)]}-${wordsB[Math.floor(Math.random() * wordsB.length)]}-${wordsC[Math.floor(Math.random() * wordsC.length)]}-${number}`;
}

function setResult(labelEl, scoreEl, reasonsEl, result, prefix) {
  if (labelEl) labelEl.textContent = result.label;
  if (scoreEl) scoreEl.textContent = `${prefix}: ${result.score}/100`;
  updateList(reasonsEl, result.reasons);
}

async function analyzeFile(file) {
  const buffer = await file.arrayBuffer();
  const digest = await crypto.subtle.digest("SHA-256", buffer);
  const hash = Array.from(new Uint8Array(digest))
    .map((byte) => byte.toString(16).padStart(2, "0"))
    .join("");
  const riskyExtension = /\.(exe|apk|js|bat|scr|msi)$/i.test(file.name);
  const label = riskyExtension ? "Review Needed" : "Clean";
  const score = riskyExtension ? 62 : 18;
  const reasons = [
    `SHA-256 hash generated: ${hash.slice(0, 18)}...`,
    riskyExtension
      ? "The file extension can carry executable risk and should be reviewed before sharing."
      : "The file type looks lower risk in this demo scanner."
  ];
  return { label, score, reasons, hash };
}

function setText(id, value) {
  const element = document.getElementById(id);
  if (element) element.textContent = value;
}

function setHTML(id, value) {
  const element = document.getElementById(id);
  if (element) element.innerHTML = value;
}

function renderHomeWidgets(state) {
  seedLogs(state);
  ensureContinuousReview(state);
  const session = state.session;
  const score = session?.otpVerified ? calculateOverallScore(state) : 82;
  setText("hero-score", String(score));
  setText(
    "home-score-summary",
    session?.otpVerified ? scoreSummary(score) : "Sign in to generate your own personalized security score and recommendations."
  );
  setText(
    "home-session-status",
    session?.otpVerified
      ? `${session.name} is verified with ${session.trust.verificationMethods.join(", ")}.`
      : "No verified session yet. Use the quick login below to explore the platform."
  );
}

function renderDashboardPage(state) {
  const shell = document.getElementById("dashboard-shell");
  if (!shell) return;

  seedLogs(state);
  ensureContinuousReview(state);
  const session = state.session;
  const verified = Boolean(session && session.otpVerified);

  const metricDefaults = {
    "sidebar-session-status": "No verified session",
    "sidebar-security-score": "0",
    "sidebar-score-summary": "Login from the home page to generate a real dashboard.",
    "dashboard-session-status": "Please verify OTP from the home page first.",
    "dashboard-name": "Pending",
    "dashboard-role": "Pending",
    "dashboard-trust": "Pending",
    "dashboard-device": "Pending",
    "dashboard-browser": "Pending",
    "dashboard-zone": "Pending",
    "dashboard-otp-count": "0"
  };

  if (!verified) {
    Object.entries(metricDefaults).forEach(([id, value]) => setText(id, value));
    setText("metric-active-users", "0");
    setText("metric-blocked-attacks", String(state.logs.filter((item) => item.level === "warning").length));
    setText("metric-suspicious-devices", "0");
    setText("metric-system-health", "98%");
    setText("metric-threat-level", "Low");
    setText("metric-device-trust", "Pending");
    setText("metric-session-risk", "Pending");
    setText("metric-verification-stack", "Pending");
    setText("recent-link-result", state.toolHistory.link ? `${state.toolHistory.link.label} (${state.toolHistory.link.score}/100)` : "No scans yet");
    setText("recent-password-result", state.toolHistory.password ? `${state.toolHistory.password.label} (${state.toolHistory.password.score}/100)` : "No scans yet");
    setText("recent-scam-result", state.toolHistory.scam ? `${state.toolHistory.scam.label} (${state.toolHistory.scam.score}/100)` : "No scans yet");
    setText("recent-file-result", state.toolHistory.file ? `${state.toolHistory.file.label} (${state.toolHistory.file.score}/100)` : "No scans yet");
    updateList(document.getElementById("dashboard-role-list"), ["Verify a user session to see role-specific access guidance."]);
    updateList(document.getElementById("dashboard-tips"), [
      "Start with a quick login from the home page.",
      "Use the tools page to scan a suspicious link or message.",
      "Return here for personalized recommendations and risk posture."
    ]);
    renderActivityFeed(state.logs);
    renderAdminFeed(state, false);
    return;
  }

  const overallScore = calculateOverallScore(state);
  setText("sidebar-session-status", `${session.name} verified`);
  setText("sidebar-security-score", String(overallScore));
  setText("sidebar-score-summary", scoreSummary(overallScore));
  setText("dashboard-session-status", `${session.name} is verified and monitored under ${session.role} policy.`);
  setText("dashboard-name", session.name);
  setText("dashboard-role", session.role);
  setText("dashboard-trust", `${session.trust.status} (${session.trust.score}/100)`);
  setText("dashboard-device", `${session.trust.device} | ${session.trust.os}`);
  setText("dashboard-browser", session.trust.browser);
  setText("dashboard-zone", session.trust.networkZone);
  setText("dashboard-otp-count", String(session.otpUsageCount));

  setText("metric-active-users", "124");
  setText("metric-blocked-attacks", String(7 + state.logs.filter((item) => item.level === "warning").length));
  setText("metric-suspicious-devices", session.trust.deviceTrust === "Trusted" ? "1" : "3");
  setText("metric-system-health", `${Math.max(88, overallScore)}%`);
  setText("metric-threat-level", session.trust.threatLevel);
  setText("metric-device-trust", session.trust.deviceTrust);
  setText("metric-session-risk", session.trust.riskLevel);
  setText("metric-verification-stack", session.trust.verificationMethods.join(" + "));

  setText("recent-link-result", state.toolHistory.link ? `${state.toolHistory.link.label} (${state.toolHistory.link.score}/100)` : "Not scanned yet");
  setText(
    "recent-password-result",
    state.toolHistory.password ? `${state.toolHistory.password.label} (${state.toolHistory.password.score}/100)` : "Not checked yet"
  );
  setText("recent-scam-result", state.toolHistory.scam ? `${state.toolHistory.scam.label} (${state.toolHistory.scam.score}/100)` : "Not analyzed yet");
  setText("recent-file-result", state.toolHistory.file ? `${state.toolHistory.file.label} (${state.toolHistory.file.score}/100)` : "Not scanned yet");

  const recommendations = [...session.trust.reasons];
  recommendations.push(`Device fingerprint: ${session.trust.deviceFingerprint}`);
  if (!state.toolHistory.link) recommendations.push("Use the phishing checker before opening internship, scholarship, or payment links.");
  if (!state.toolHistory.password) recommendations.push("Run the password analyzer to understand how crack-resistant your password really is.");
  if (!state.toolHistory.scam) recommendations.push("Paste suspicious messages into the scam detector before replying.");
  if (!state.toolHistory.file) recommendations.push("Use the file scanner before trusting files shared through chat, email, or campus groups.");
  if (!state.challengeSolved) recommendations.push("Complete the daily challenge in Learning Hub to improve awareness and score.");
  updateList(document.getElementById("dashboard-tips"), recommendations);
  updateList(document.getElementById("dashboard-role-list"), roleContent[session.role]);

  renderActivityFeed(state.logs);
  renderAdminFeed(state, session.role === "admin" || session.role === "analyst");
  renderThreatMap(session);
}

function renderActivityFeed(logs) {
  const target = document.getElementById("live-activity-feed");
  if (!target) return;
  target.innerHTML = "";
  logs.slice(0, 6).forEach((log) => {
    const row = document.createElement("div");
    row.className = "feed-item";
    row.innerHTML = `<strong>[${formatTimestamp(log.timestamp)}] ${log.title}</strong><span>${log.detail}</span>`;
    target.appendChild(row);
  });
}

function renderAdminFeed(state, canView) {
  const target = document.getElementById("admin-feed");
  if (!target) return;
  if (!canView) {
    target.innerHTML = '<div class="feed-item"><strong>Restricted</strong><span>Admin and analyst roles can view full monitoring data.</span></div>';
    return;
  }
  target.innerHTML = "";
  const visible = state.events.length ? state.events : [{ name: "No activity yet", role: "system", browser: "Pending", device: "Pending", timestamp: nowIso() }];
  visible.slice(0, 8).forEach((item) => {
    const row = document.createElement("div");
    row.className = "feed-item";
    row.innerHTML = `<strong>${item.name}</strong><span>${item.role} | ${item.browser} | ${item.device} | ${formatTimestamp(item.timestamp)}</span>`;
    target.appendChild(row);
  });
}

function renderThreatMap(session) {
  setText("map-location", session ? `${session.trust.locale} | ${session.trust.timezone}` : "Pending");
  setText("map-vpn", session ? (session.trust.vpnDetected ? "VPN-like pattern detected" : "No VPN signal in demo") : "Pending");
  setText("map-travel", session ? (session.trust.impossibleTravel ? "Impossible travel flagged" : "No travel conflict detected") : "Pending");
}

function renderToolsSnapshot(state) {
  setText("tool-summary-link", state.toolHistory.link ? `${state.toolHistory.link.label} (${state.toolHistory.link.score}/100)` : "Waiting for scan");
  setText(
    "tool-summary-password",
    state.toolHistory.password ? `${state.toolHistory.password.label} (${state.toolHistory.password.score}/100)` : "Waiting for scan"
  );
  setText("tool-summary-scam", state.toolHistory.scam ? `${state.toolHistory.scam.label} (${state.toolHistory.scam.score}/100)` : "Waiting for scan");
  setText("tool-summary-file", state.toolHistory.file ? `${state.toolHistory.file.label} (${state.toolHistory.file.score}/100)` : "Waiting for scan");
}

function renderThreatPage(state) {
  const feed = document.getElementById("threat-feed");
  if (!feed) return;
  feed.innerHTML = "";
  const source = state.logs.slice(0, 8);
  source.forEach((log) => {
    const card = document.createElement("article");
    card.className = "news-card";
    card.innerHTML = `<span class="pill ${log.level === "warning" ? "warning" : log.level === "success" ? "success" : ""}">${log.category}</span><h3>${log.title}</h3><p>${log.detail}</p>`;
    feed.appendChild(card);
  });
}

function renderAuditLogsPage(state) {
  const list = document.getElementById("audit-log-list");
  if (!list) return;
  setText("log-total-events", String(state.logs.length));
  setText("log-blocked-events", String(state.logs.filter((log) => log.level === "warning").length));
  setText("log-auth-events", String(state.logs.filter((log) => log.category === "auth").length));
  list.innerHTML = "";
  state.logs.slice(0, 20).forEach((log) => {
    const row = document.createElement("div");
    row.className = "feed-item";
    row.innerHTML = `<strong>${log.title}</strong><span>${formatTimestamp(log.timestamp)} | ${log.category} | ${log.detail}</span>`;
    list.appendChild(row);
  });
}

function renderSettingsPage(state) {
  const form = document.getElementById("settings-form");
  if (!form) return;
  const settings = state.settings;
  const fields = [
    ["setting-email-otp", settings.emailOtp],
    ["setting-phone-otp", settings.phoneOtp],
    ["setting-google-auth", settings.googleAuth],
    ["setting-biometric", settings.biometric],
    ["setting-device-fingerprint", settings.deviceFingerprinting],
    ["setting-continuous-auth", settings.continuousAuth]
  ];
  fields.forEach(([id, value]) => {
    const field = document.getElementById(id);
    if (field) field.checked = value;
  });
  const summary = activeVerificationMethods(settings).join(", ");
  setText("settings-summary", `Active verification stack: ${summary}`);
}

function renderScorePage(state) {
  const target = document.getElementById("score-overview");
  if (!target) return;
  const session = state.session;
  if (!session || !session.otpVerified) {
    target.innerHTML = "<strong>Score unavailable</strong><p>Verify a session to calculate a Zero Trust posture score.</p>";
    return;
  }
  const overallScore = calculateOverallScore(state);
  target.innerHTML = `<strong>${overallScore}/100</strong><p>${scoreSummary(overallScore)}</p>`;
}

function initDashboardTabs() {
  const tabButtons = Array.from(document.querySelectorAll("[data-dashboard-view]"));
  const views = Array.from(document.querySelectorAll(".dashboard-view"));
  if (!tabButtons.length || !views.length) return;

  const setView = (name) => {
    tabButtons.forEach((button) => button.classList.toggle("active", button.dataset.dashboardView === name));
    views.forEach((view) => view.classList.toggle("active", view.dataset.dashboardPanel === name));
  };

  tabButtons.forEach((button) => button.addEventListener("click", () => setView(button.dataset.dashboardView)));
  setView("overview");
}

function initLoginFlow() {
  const loginForm = document.getElementById("login-form");
  const otpForm = document.getElementById("otp-form");
  const regenerateBtn = document.getElementById("regenerate-btn");
  const logoutBtn = document.getElementById("logout-btn");
  const loginMessage = document.getElementById("login-message");
  const otpMessage = document.getElementById("otp-message");
  const otpDisplay = document.getElementById("otp-display-value");

  if (loginForm) {
    loginForm.addEventListener("submit", (event) => {
      event.preventDefault();
      if (loginMessage) loginMessage.textContent = "";
      if (otpMessage) otpMessage.textContent = "";

      const data = new FormData(loginForm);
      const username = data.get("username");
      const password = data.get("password");
      const user = users[username];
      const state = readState();

      if (!user || user.password !== password) {
        state.failedAttempts += 1;
        recordLog(state, "warning", "Failed login attempt", `Rejected credential attempt for username ${username || "unknown"}.`, "auth");
        writeState(state);
        if (loginMessage) loginMessage.textContent = "Invalid credentials.";
        renderAll();
        return;
      }

      state.failedAttempts = 0;
      const previous = state.session && state.session.username === user.username ? state.session : null;
      state.session = buildSession(user, previous, state);
      recordEvent(state, state.session, "login-issued", "Primary login accepted");
      recordLog(state, "info", "Primary identity verified", `${state.session.name} passed password verification and received an OTP challenge.`, "auth");
      writeState(state);

      if (otpDisplay) otpDisplay.textContent = state.session.otp;
      if (loginMessage) loginMessage.textContent = `Login accepted. OTP generated for ${state.session.role}.`;
      renderAll();
    });
  }

  if (otpForm) {
    otpForm.addEventListener("submit", (event) => {
      event.preventDefault();
      const state = readState();
      const session = state.session;
      if (otpMessage) otpMessage.textContent = "";

      if (!session) {
        if (otpMessage) otpMessage.textContent = "Sign in first.";
        return;
      }

      const otpValue = document.getElementById("otp-input")?.value;
      if (otpValue !== session.otp) {
        recordLog(state, "warning", "OTP verification failed", `A bad OTP was entered for ${session.name}.`, "auth");
        writeState(state);
        if (otpMessage) otpMessage.textContent = "Incorrect OTP.";
        renderAll();
        return;
      }

      session.otpVerified = true;
      session.otp = null;
      session.lastSeenAt = nowIso();
      session.nextReviewAt = new Date(Date.now() + 3 * 60 * 1000).toISOString();
      state.session = session;
      recordEvent(state, session, "otp-verified", "Step-up verification completed");
      recordLog(state, "success", "MFA verification completed", `${session.name} completed the ${session.trust.verificationMethods.join(" + ")} flow.`, "auth");
      writeState(state);

      if (otpDisplay) otpDisplay.textContent = "Used";
      if (otpMessage) otpMessage.textContent = "OTP verified. You can now use the platform.";
      otpForm.reset();
      renderAll();
    });
  }

  if (regenerateBtn) {
    regenerateBtn.addEventListener("click", () => {
      const state = readState();
      const session = state.session;
      if (!session) {
        if (otpMessage) otpMessage.textContent = "Sign in first.";
        return;
      }

      session.otp = generateOtp(session.otp);
      session.otpVerified = false;
      session.lastSeenAt = nowIso();
      session.otpUsageCount += 1;
      state.session = session;
      recordLog(state, "info", "New OTP issued", `A replacement OTP was generated for ${session.name}.`, "auth");
      writeState(state);

      if (otpDisplay) otpDisplay.textContent = session.otp;
      if (otpMessage) otpMessage.textContent = `A different OTP has been generated. Request count: ${session.otpUsageCount}.`;
      renderAll();
    });
  }

  if (logoutBtn) {
    logoutBtn.addEventListener("click", () => {
      const state = readState();
      if (state.session) {
        recordLog(state, "info", "Session closed", `${state.session.name} signed out of the platform.`, "session");
      }
      state.session = null;
      writeState(state);
      renderAll();
    });
  }
}

function initToolsPage() {
  const linkForm = document.getElementById("link-form");
  const passwordForm = document.getElementById("password-form");
  const scamForm = document.getElementById("scam-form");
  const fileForm = document.getElementById("file-form");
  const generateBtn = document.getElementById("generate-passphrase-btn");

  if (linkForm) {
    linkForm.addEventListener("submit", (event) => {
      event.preventDefault();
      const input = document.getElementById("link-input");
      const result = analyzeLink(input.value.trim());
      const state = readState();
      state.toolHistory.link = result;
      recordLog(state, result.score >= 65 ? "warning" : "info", "Link scan completed", `Result: ${result.label} for ${result.host || "supplied URL"}.`, "scan");
      writeState(state);
      setResult(document.getElementById("link-risk-label"), document.getElementById("link-risk-score"), document.getElementById("link-reasons"), result, "Risk score");
      setText("link-message", `Scan complete for ${result.host || "the supplied link"}.`);
      renderAll();
    });
  }

  if (passwordForm) {
    passwordForm.addEventListener("submit", (event) => {
      event.preventDefault();
      const input = document.getElementById("password-check-input");
      const result = analyzePassword(input.value);
      const state = readState();
      state.toolHistory.password = result;
      recordLog(state, result.score < 45 ? "warning" : "info", "Password analysis completed", `Password health evaluated as ${result.label}.`, "scan");
      writeState(state);
      setResult(document.getElementById("password-risk-label"), document.getElementById("password-risk-score"), document.getElementById("password-reasons"), result, "Strength score");
      setText("password-message", "Password analysis complete.");
      renderAll();
    });
  }

  if (generateBtn) {
    generateBtn.addEventListener("click", () => {
      setText("generated-passphrase", generatePassphrase());
      setText("password-message", "Passphrase generated. Use it as inspiration for a safer login.");
    });
  }

  if (scamForm) {
    scamForm.addEventListener("submit", (event) => {
      event.preventDefault();
      const input = document.getElementById("scam-input");
      const result = analyzeScam(input.value.trim());
      const state = readState();
      state.toolHistory.scam = result;
      recordLog(state, result.score >= 70 ? "warning" : "info", "Scam analysis completed", `Message risk was scored as ${result.label}.`, "scan");
      writeState(state);
      setResult(document.getElementById("scam-risk-label"), document.getElementById("scam-risk-score"), document.getElementById("scam-reasons"), result, "Scam probability");
      setText("scam-message", "Scam analysis complete.");
      renderAll();
    });
  }

  if (fileForm) {
    fileForm.addEventListener("submit", async (event) => {
      event.preventDefault();
      const fileInput = document.getElementById("file-input");
      const file = fileInput?.files?.[0];
      if (!file) {
        setText("file-message", "Choose a file first.");
        return;
      }

      const result = await analyzeFile(file);
      const state = readState();
      state.toolHistory.file = result;
      recordLog(state, result.score >= 60 ? "warning" : "success", "File scan completed", `File ${file.name} reviewed with status ${result.label}.`, "scan");
      writeState(state);
      setResult(document.getElementById("file-risk-label"), document.getElementById("file-risk-score"), document.getElementById("file-reasons"), result, "File risk");
      setText("file-message", `Scan complete for ${file.name}.`);
      renderAll();
    });
  }
}

function initLearningPage() {
  Array.from(document.querySelectorAll(".challenge-btn")).forEach((button) => {
    button.addEventListener("click", () => {
      const state = readState();
      const correct = button.dataset.correct === "true";
      state.challengeSolved = correct;
      recordLog(state, correct ? "success" : "warning", "Learning challenge answered", correct ? "User selected the safest action in the phishing scenario." : "User missed the safest action in the phishing scenario.", "learning");
      writeState(state);
      setText(
        "challenge-feedback",
        correct
          ? "Correct. OTPs should never be shared, even if the request looks official."
          : "Not quite. The safest move is to refuse and verify the sender another way."
      );
      renderAll();
    });
  });
}

function initAssistantPage() {
  const assistantForm = document.getElementById("assistant-form");
  if (!assistantForm) return;

  assistantForm.addEventListener("submit", (event) => {
    event.preventDefault();
    const text = document.getElementById("assistant-input")?.value.trim() || "";
    const responseTitle = document.getElementById("assistant-response-title");
    const responseBody = document.getElementById("assistant-response-body");
    const responseList = document.getElementById("assistant-response-list");

    let result;
    if (/https?:\/\//i.test(text)) {
      result = analyzeLink(text);
      if (responseTitle) responseTitle.textContent = `Link review: ${result.label}`;
      if (responseBody) responseBody.textContent = `This looks ${result.label.toLowerCase()} with a risk score of ${result.score}/100.`;
    } else {
      result = analyzeScam(text);
      if (responseTitle) responseTitle.textContent = `Message review: ${result.label}`;
      if (responseBody) responseBody.textContent = `This message carries a scam probability of ${result.score}/100.`;
    }

    updateList(responseList, result.reasons);
  });
}

function initSettingsPage() {
  const form = document.getElementById("settings-form");
  if (!form) return;
  form.addEventListener("submit", (event) => {
    event.preventDefault();
    const state = readState();
    state.settings.emailOtp = Boolean(document.getElementById("setting-email-otp")?.checked);
    state.settings.phoneOtp = Boolean(document.getElementById("setting-phone-otp")?.checked);
    state.settings.googleAuth = Boolean(document.getElementById("setting-google-auth")?.checked);
    state.settings.biometric = Boolean(document.getElementById("setting-biometric")?.checked);
    state.settings.deviceFingerprinting = Boolean(document.getElementById("setting-device-fingerprint")?.checked);
    state.settings.continuousAuth = Boolean(document.getElementById("setting-continuous-auth")?.checked);

    if (state.session) {
      const user = Object.values(users).find((item) => item.username === state.session.username);
      if (user) {
        const refreshed = buildSession(user, state.session, state);
        refreshed.otpVerified = state.session.otpVerified;
        refreshed.otp = state.session.otp;
        refreshed.createdAt = state.session.createdAt;
        state.session = refreshed;
      }
    }

    recordLog(state, "success", "Settings updated", `Verification stack changed to ${activeVerificationMethods(state.settings).join(", ")}.`, "policy");
    writeState(state);
    setText("settings-message", "Settings saved in demo storage.");
    renderAll();
  });
}

function renderAll() {
  const state = readState();
  seedLogs(state);
  ensureContinuousReview(state);
  writeState(state);
  renderHomeWidgets(state);
  renderDashboardPage(state);
  renderToolsSnapshot(state);
  renderThreatPage(state);
  renderAuditLogsPage(state);
  renderSettingsPage(state);
  renderScorePage(state);
}

window.addEventListener("storage", renderAll);

document.addEventListener("DOMContentLoaded", () => {
  initLoginFlow();
  initDashboardTabs();
  initToolsPage();
  initLearningPage();
  initAssistantPage();
  initSettingsPage();
  renderAll();
});
