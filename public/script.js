const STORAGE_KEY = "secureu-ecosystem";

const users = {
  admin: { username: "admin", password: "Admin@123", role: "admin", name: "Campus Admin" },
  employee: { username: "employee", password: "Employee@123", role: "student", name: "Student Member" },
  guest: { username: "guest", password: "Guest@123", role: "guest", name: "Guest Visitor" }
};

const roleContent = {
  admin: [
    "Monitor student usage patterns and suspicious activity signals",
    "Review which security tools students use most often",
    "Track awareness progress across shared demo accounts"
  ],
  student: [
    "Scan risky links before opening them",
    "Analyze password strength and improve account safety",
    "Review scam messages and learn safer online habits"
  ],
  guest: [
    "Access beginner-friendly safety checks and awareness content",
    "Use the learning tools without platform monitoring controls",
    "Explore simple digital safety guidance in a limited environment"
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
    "This demo uses role, device type, and browser context to estimate a simple trust score.",
    "The platform keeps access limited until login and OTP verification are complete."
  ];

  if (device === "Desktop") {
    score += 8;
    reasons.push("Desktop usage is treated as slightly lower risk for study and work tasks.");
  } else {
    score -= 4;
    reasons.push("Mobile access is flexible, but it should be used carefully for sensitive tasks.");
  }

  if (role === "admin") {
    score -= 6;
    reasons.push("Admin sessions need stronger monitoring because they can see more platform activity.");
  } else if (role === "student") {
    score += 4;
    reasons.push("Student mode unlocks the full safety toolkit with limited platform risk.");
  } else {
    score -= 8;
    reasons.push("Guest mode keeps access limited and guidance-focused.");
  }

  let status = "Guided Access";
  let decision = "Basic tools are available with monitoring and OTP protection.";

  if (score >= 78) {
    status = "Trusted";
    decision = "Full role access is available inside the platform.";
  } else if (score < 62) {
    status = "Restricted";
    decision = "Use only limited features until trust improves.";
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

function scoreSummary(score) {
  if (score >= 85) return "Excellent. You are following strong personal safety habits.";
  if (score >= 70) return "Good. A few small changes can make you noticeably safer online.";
  if (score >= 55) return "Fair. You are protected in some areas, but there are still weak points.";
  return "Needs attention. Review passwords, suspicious messages, and risky links soon.";
}

function calculateOverallScore(state) {
  const session = state.session;
  if (!session || !session.otpVerified) return 0;
  let score = session.trust.score;
  if (state.toolHistory.link && state.toolHistory.link.score <= 35) score += 4;
  if (state.toolHistory.password && state.toolHistory.password.score >= 75) score += 6;
  if (state.toolHistory.scam && state.toolHistory.scam.score <= 30) score += 4;
  if (state.challengeSolved) score += 8;
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

function renderHomeWidgets(state) {
  const heroScore = document.getElementById("hero-score");
  const homeSummary = document.getElementById("home-score-summary");
  if (heroScore) {
    const score = state.session?.otpVerified ? calculateOverallScore(state) : 82;
    heroScore.textContent = String(score);
  }
  if (homeSummary) {
    homeSummary.textContent = state.session?.otpVerified
      ? scoreSummary(calculateOverallScore(state))
      : "Sign in to generate your own personalized security score and recommendations.";
  }

  const homeSession = document.getElementById("home-session-status");
  if (homeSession) {
    homeSession.textContent = state.session?.otpVerified
      ? `${state.session.name} is verified and can continue into the platform dashboard.`
      : "No verified session yet. Use the quick login below to explore the product.";
  }
}

function renderDashboardPage(state) {
  const workspaceRoot = document.getElementById("dashboard-shell");
  if (!workspaceRoot) return;

  const session = state.session;
  const verified = Boolean(session && session.otpVerified);
  const sidebarStatus = document.getElementById("sidebar-session-status");
  const sidebarScore = document.getElementById("sidebar-security-score");
  const sidebarSummary = document.getElementById("sidebar-score-summary");
  const dashboardStatus = document.getElementById("dashboard-session-status");
  const dashboardName = document.getElementById("dashboard-name");
  const dashboardRole = document.getElementById("dashboard-role");
  const dashboardTrust = document.getElementById("dashboard-trust");
  const dashboardDevice = document.getElementById("dashboard-device");
  const dashboardBrowser = document.getElementById("dashboard-browser");
  const dashboardZone = document.getElementById("dashboard-zone");
  const dashboardOtp = document.getElementById("dashboard-otp-count");
  const recentLink = document.getElementById("recent-link-result");
  const recentPassword = document.getElementById("recent-password-result");
  const recentScam = document.getElementById("recent-scam-result");
  const dashboardTips = document.getElementById("dashboard-tips");
  const adminFeed = document.getElementById("admin-feed");

  if (!verified) {
    if (sidebarStatus) sidebarStatus.textContent = "No verified session";
    if (sidebarScore) sidebarScore.textContent = "0";
    if (sidebarSummary) sidebarSummary.textContent = "Login from the home page to generate a real dashboard.";
    if (dashboardStatus) dashboardStatus.textContent = "Please verify OTP from the home page first.";
    if (dashboardName) dashboardName.textContent = "Pending";
    if (dashboardRole) dashboardRole.textContent = "Pending";
    if (dashboardTrust) dashboardTrust.textContent = "Pending";
    if (dashboardDevice) dashboardDevice.textContent = "Pending";
    if (dashboardBrowser) dashboardBrowser.textContent = "Pending";
    if (dashboardZone) dashboardZone.textContent = "Pending";
    if (dashboardOtp) dashboardOtp.textContent = "0";
    if (recentLink) recentLink.textContent = "No scans yet";
    if (recentPassword) recentPassword.textContent = "No scans yet";
    if (recentScam) recentScam.textContent = "No scans yet";
    updateList(dashboardTips, [
      "Start with a quick login from the home page.",
      "Use the tools page to scan a suspicious link or message.",
      "Return here for personalized recommendations."
    ]);
    if (adminFeed) {
      adminFeed.innerHTML = '<div class="feed-item"><strong>No activity yet</strong><span>Admin data appears after verified usage.</span></div>';
    }
    return;
  }

  const overallScore = calculateOverallScore(state);
  if (sidebarStatus) sidebarStatus.textContent = `${session.name} verified`;
  if (sidebarScore) sidebarScore.textContent = String(overallScore);
  if (sidebarSummary) sidebarSummary.textContent = scoreSummary(overallScore);
  if (dashboardStatus) dashboardStatus.textContent = `${session.name} is verified and using ${session.role} access.`;
  if (dashboardName) dashboardName.textContent = session.name;
  if (dashboardRole) dashboardRole.textContent = session.role;
  if (dashboardTrust) dashboardTrust.textContent = `${session.trust.status} (${session.trust.score}/100)`;
  if (dashboardDevice) dashboardDevice.textContent = session.trust.device;
  if (dashboardBrowser) dashboardBrowser.textContent = session.trust.browser;
  if (dashboardZone) dashboardZone.textContent = session.trust.networkZone;
  if (dashboardOtp) dashboardOtp.textContent = String(session.otpUsageCount);
  if (recentLink) recentLink.textContent = state.toolHistory.link ? `${state.toolHistory.link.label} (${state.toolHistory.link.score}/100)` : "Not scanned yet";
  if (recentPassword) {
    recentPassword.textContent = state.toolHistory.password
      ? `${state.toolHistory.password.label} (${state.toolHistory.password.score}/100)`
      : "Not checked yet";
  }
  if (recentScam) {
    recentScam.textContent = state.toolHistory.scam ? `${state.toolHistory.scam.label} (${state.toolHistory.scam.score}/100)` : "Not analyzed yet";
  }

  const tips = [...session.trust.reasons];
  if (!state.toolHistory.link) tips.push("Use the phishing checker before opening internship, scholarship, or payment links.");
  if (!state.toolHistory.password) tips.push("Run the password analyzer to understand how crack-resistant your password really is.");
  if (!state.toolHistory.scam) tips.push("Paste suspicious messages into the scam detector before replying.");
  if (!state.challengeSolved) tips.push("Complete the daily challenge in Learning Hub to improve awareness and score.");
  updateList(dashboardTips, tips);

  if (adminFeed) {
    if (session.role !== "admin") {
      adminFeed.innerHTML = '<div class="feed-item"><strong>Admin only</strong><span>This monitoring view is available only for admin login.</span></div>';
    } else if (!state.events.filter((item) => item.role !== "admin").length) {
      adminFeed.innerHTML = '<div class="feed-item"><strong>No student or guest events yet</strong><span>Activity appears after other users sign in.</span></div>';
    } else {
      adminFeed.innerHTML = "";
      state.events
        .filter((item) => item.role !== "admin")
        .forEach((item) => {
          const row = document.createElement("div");
          row.className = "feed-item";
          row.innerHTML = `<strong>${item.name}</strong><span>${item.role} | ${item.browser} | ${item.device} | ${formatTimestamp(item.timestamp)}</span>`;
          adminFeed.appendChild(row);
        });
    }
  }

  const dashboardRoleList = document.getElementById("dashboard-role-list");
  if (dashboardRoleList) {
    updateList(dashboardRoleList, roleContent[session.role]);
  }
}

function initDashboardTabs() {
  const tabButtons = Array.from(document.querySelectorAll("[data-dashboard-view]"));
  const views = Array.from(document.querySelectorAll(".dashboard-view"));
  if (!tabButtons.length || !views.length) return;

  const setView = (name) => {
    tabButtons.forEach((button) => {
      button.classList.toggle("active", button.dataset.dashboardView === name);
    });
    views.forEach((view) => {
      view.classList.toggle("active", view.dataset.dashboardPanel === name);
    });
  };

  tabButtons.forEach((button) => {
    button.addEventListener("click", () => setView(button.dataset.dashboardView));
  });

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

      if (!user || user.password !== password) {
        if (loginMessage) loginMessage.textContent = "Invalid credentials.";
        return;
      }

      const state = readState();
      const previous = state.session && state.session.username === user.username ? state.session : null;
      state.session = buildSession(user, previous);
      recordEvent(state, state.session, "login-issued");
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
        if (otpMessage) otpMessage.textContent = "Incorrect OTP.";
        return;
      }

      session.otpVerified = true;
      session.otp = null;
      session.lastSeenAt = nowIso();
      state.session = session;
      recordEvent(state, session, "otp-verified");
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
      writeState(state);

      if (otpDisplay) otpDisplay.textContent = session.otp;
      if (otpMessage) otpMessage.textContent = `A different OTP has been generated. Request count: ${session.otpUsageCount}.`;
      renderAll();
    });
  }

  if (logoutBtn) {
    logoutBtn.addEventListener("click", () => {
      const state = readState();
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
  const generateBtn = document.getElementById("generate-passphrase-btn");

  if (linkForm) {
    linkForm.addEventListener("submit", (event) => {
      event.preventDefault();
      const input = document.getElementById("link-input");
      const result = analyzeLink(input.value.trim());
      const state = readState();
      state.toolHistory.link = result;
      writeState(state);
      setResult(
        document.getElementById("link-risk-label"),
        document.getElementById("link-risk-score"),
        document.getElementById("link-reasons"),
        result,
        "Risk score"
      );
      const message = document.getElementById("link-message");
      if (message) message.textContent = `Scan complete for ${result.host || "the supplied link"}.`;
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
      writeState(state);
      setResult(
        document.getElementById("password-risk-label"),
        document.getElementById("password-risk-score"),
        document.getElementById("password-reasons"),
        result,
        "Strength score"
      );
      const message = document.getElementById("password-message");
      if (message) message.textContent = "Password analysis complete.";
      renderAll();
    });
  }

  if (generateBtn) {
    generateBtn.addEventListener("click", () => {
      const target = document.getElementById("generated-passphrase");
      if (target) target.textContent = generatePassphrase();
      const message = document.getElementById("password-message");
      if (message) message.textContent = "Passphrase generated. Use it as inspiration for a safer login.";
    });
  }

  if (scamForm) {
    scamForm.addEventListener("submit", (event) => {
      event.preventDefault();
      const input = document.getElementById("scam-input");
      const result = analyzeScam(input.value.trim());
      const state = readState();
      state.toolHistory.scam = result;
      writeState(state);
      setResult(
        document.getElementById("scam-risk-label"),
        document.getElementById("scam-risk-score"),
        document.getElementById("scam-reasons"),
        result,
        "Scam probability"
      );
      const message = document.getElementById("scam-message");
      if (message) message.textContent = "Scam analysis complete.";
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
      writeState(state);
      const feedback = document.getElementById("challenge-feedback");
      if (feedback) {
        feedback.textContent = correct
          ? "Correct. OTPs should never be shared, even if the request looks official."
          : "Not quite. The safest move is to refuse and verify the sender another way.";
      }
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

function renderAll() {
  const state = readState();
  renderHomeWidgets(state);
  renderDashboardPage(state);
}

window.addEventListener("storage", renderAll);

document.addEventListener("DOMContentLoaded", () => {
  initLoginFlow();
  initDashboardTabs();
  initToolsPage();
  initLearningPage();
  initAssistantPage();
  renderAll();
});
