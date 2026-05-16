require("dotenv").config();

const crypto = require("crypto");
const path = require("path");
const bcrypt = require("bcryptjs");
const compression = require("compression");
const cookieParser = require("cookie-parser");
const cors = require("cors");
const csrf = require("csurf");
const express = require("express");
const mongoSanitize = require("express-mongo-sanitize");
const rateLimit = require("express-rate-limit");
const helmet = require("helmet");
const hpp = require("hpp");
const jwt = require("jsonwebtoken");
const mongoose = require("mongoose");
const nodemailer = require("nodemailer");
const { createClient } = require("redis");
const twilio = require("twilio");
const xss = require("xss-clean");

const PORT = process.env.PORT || 3000;
const IS_PRODUCTION = process.env.NODE_ENV === "production";
const JWT_SECRET = process.env.JWT_SECRET || "development-only-change-this-secret";
const OTP_SECRET = process.env.OTP_SECRET || "development-only-change-this-otp-secret";
const OTP_EXPIRES_SECONDS = Number(process.env.OTP_EXPIRES_SECONDS || 300);
const OTP_RESEND_SECONDS = Number(process.env.OTP_RESEND_SECONDS || 60);
const SESSION_EXPIRES_SECONDS = Number(process.env.SESSION_EXPIRES_SECONDS || 86400);
const PUBLIC_APP_URL = process.env.PUBLIC_APP_URL || `http://localhost:${PORT}`;

const app = express();
let infrastructureReady = null;
const memoryUsers = new Map();
const memoryOtpStore = new Map();
const memorySessions = new Map();

let redisClient = null;
let mailer = null;
let whatsAppClient = null;

const roleContent = {
  admin: {
    title: "Admin Control Center",
    items: ["Approve sensitive access requests", "Review OTP request analytics", "Audit device sessions"]
  },
  employee: {
    title: "Employee Workspace",
    items: ["View assigned internal resources", "Confirm device trust", "Request temporary elevated permissions"]
  },
  analyst: {
    title: "Security Analyst Console",
    items: ["Review alerts", "Investigate login history", "Monitor risky devices"]
  },
  guest: {
    title: "Guest Access Portal",
    items: ["Use time-limited visitor access", "Stay isolated from sensitive systems", "Complete awareness checks"]
  }
};

const userSchema = new mongoose.Schema(
  {
    name: { type: String, required: true, trim: true, maxlength: 80 },
    email: { type: String, required: true, unique: true, lowercase: true, trim: true },
    phone: { type: String, trim: true },
    passwordHash: { type: String, required: true },
    role: { type: String, enum: ["admin", "employee", "analyst", "guest"], default: "employee" },
    isEmailVerified: { type: Boolean, default: false },
    isWhatsAppVerified: { type: Boolean, default: false },
    mfaEnabled: { type: Boolean, default: true },
    failedLoginCount: { type: Number, default: 0 },
    lastLoginAt: Date
  },
  { timestamps: true }
);

const loginEventSchema = new mongoose.Schema(
  {
    userId: { type: mongoose.Schema.Types.ObjectId, ref: "User", index: true },
    email: String,
    status: { type: String, enum: ["success", "failed", "otp_sent", "otp_verified", "logout", "reset"], default: "success" },
    channel: String,
    ip: String,
    userAgent: String,
    deviceId: String,
    detail: String
  },
  { timestamps: true }
);

const securityAlertSchema = new mongoose.Schema(
  {
    userId: { type: mongoose.Schema.Types.ObjectId, ref: "User", index: true },
    level: { type: String, enum: ["info", "warning", "critical"], default: "info" },
    title: String,
    detail: String,
    ip: String,
    userAgent: String
  },
  { timestamps: true }
);

const sessionSchema = new mongoose.Schema(
  {
    userId: { type: mongoose.Schema.Types.ObjectId, ref: "User", index: true },
    tokenId: { type: String, unique: true, index: true },
    deviceId: String,
    ip: String,
    userAgent: String,
    lastSeenAt: Date,
    expiresAt: Date,
    revokedAt: Date
  },
  { timestamps: true }
);

const User = mongoose.models.User || mongoose.model("User", userSchema);
const LoginEvent = mongoose.models.LoginEvent || mongoose.model("LoginEvent", loginEventSchema);
const SecurityAlert = mongoose.models.SecurityAlert || mongoose.model("SecurityAlert", securityAlertSchema);
const Session = mongoose.models.Session || mongoose.model("Session", sessionSchema);

function requireEnv(name) {
  if (!process.env[name] && IS_PRODUCTION) {
    console.warn(`Missing production environment variable: ${name}`);
  }
}

async function seedInitialUser() {
  if (!process.env.SEED_USER_EMAIL || !process.env.SEED_USER_PASSWORD) return;
  const email = normalizeEmail(process.env.SEED_USER_EMAIL);
  const existing = await findUserByEmail(email);
  if (existing) return;
  await createUser({
    name: process.env.SEED_USER_NAME || "SecureU User",
    email,
    phone: process.env.SEED_USER_PHONE || "",
    passwordHash: await bcrypt.hash(process.env.SEED_USER_PASSWORD, 12),
    role: process.env.SEED_USER_ROLE || "admin",
    isEmailVerified: true,
    isWhatsAppVerified: Boolean(process.env.SEED_USER_PHONE),
    mfaEnabled: true
  });
  console.log(`Seeded initial SecureU user: ${email}`);
}

function createMemoryUser(data) {
  const user = {
    _id: crypto.randomUUID(),
    name: data.name,
    email: normalizeEmail(data.email),
    phone: data.phone || "",
    passwordHash: data.passwordHash,
    role: data.role || "employee",
    isEmailVerified: Boolean(data.isEmailVerified),
    isWhatsAppVerified: Boolean(data.isWhatsAppVerified),
    mfaEnabled: data.mfaEnabled !== false,
    failedLoginCount: data.failedLoginCount || 0,
    lastLoginAt: data.lastLoginAt || null,
    createdAt: new Date(),
    updatedAt: new Date(),
    async save() {
      this.updatedAt = new Date();
      memoryUsers.set(this.email, this);
      return this;
    }
  };
  memoryUsers.set(user.email, user);
  return user;
}

async function findUserByEmail(email) {
  const normalizedEmail = normalizeEmail(email);
  if (mongoose.connection.readyState === 1) return User.findOne({ email: normalizedEmail });
  return memoryUsers.get(normalizedEmail) || null;
}

async function findUserById(id) {
  if (mongoose.connection.readyState === 1) return User.findById(id).select("-passwordHash");
  return Array.from(memoryUsers.values()).find((user) => String(user._id) === String(id)) || null;
}

async function createUser(data) {
  if (mongoose.connection.readyState === 1) return User.create(data);
  return createMemoryUser(data);
}

function normalizeEmail(email) {
  return String(email || "").trim().toLowerCase();
}

function normalizeChannel(channel) {
  return channel === "whatsapp" ? "whatsapp" : "email";
}

function publicUser(user) {
  return {
    id: user._id,
    name: user.name,
    email: user.email,
    phone: user.phone,
    role: user.role,
    isEmailVerified: user.isEmailVerified,
    isWhatsAppVerified: user.isWhatsAppVerified,
    mfaEnabled: user.mfaEnabled
  };
}

function hashOtp(otp) {
  return crypto.createHmac("sha256", OTP_SECRET).update(String(otp)).digest("hex");
}

function generateOtp() {
  return crypto.randomInt(100000, 1000000).toString();
}

function getClientIp(request) {
  return request.headers["x-forwarded-for"]?.split(",")[0]?.trim() || request.socket.remoteAddress || "unknown";
}

function getDeviceId(request, response) {
  const existing = request.cookies.device_id;
  if (existing) return existing;
  const deviceId = crypto.randomUUID();
  response.cookie("device_id", deviceId, {
    httpOnly: true,
    sameSite: "strict",
    secure: IS_PRODUCTION,
    maxAge: 1000 * 60 * 60 * 24 * 365
  });
  return deviceId;
}

function otpKey(userId, purpose) {
  return `otp:${purpose}:${userId}`;
}

function resendKey(userId, purpose) {
  return `otp-resend:${purpose}:${userId}`;
}

function resetKey(token) {
  return `reset:${token}`;
}

async function cacheSet(key, value, ttlSeconds) {
  const payload = JSON.stringify(value);
  if (redisClient?.isOpen) {
    await redisClient.set(key, payload, { EX: ttlSeconds });
    return;
  }
  memoryOtpStore.set(key, { payload, expiresAt: Date.now() + ttlSeconds * 1000 });
}

async function cacheGet(key) {
  if (redisClient?.isOpen) {
    const value = await redisClient.get(key);
    return value ? JSON.parse(value) : null;
  }
  const item = memoryOtpStore.get(key);
  if (!item) return null;
  if (item.expiresAt < Date.now()) {
    memoryOtpStore.delete(key);
    return null;
  }
  return JSON.parse(item.payload);
}

async function cacheDelete(key) {
  if (redisClient?.isOpen) {
    await redisClient.del(key);
    return;
  }
  memoryOtpStore.delete(key);
}

async function trackEvent(request, user, status, detail, channel) {
  const event = {
    userId: user?._id,
    email: user?.email || request.body?.email,
    status,
    channel,
    ip: getClientIp(request),
    userAgent: request.headers["user-agent"] || "unknown",
    deviceId: request.cookies.device_id,
    detail
  };
  if (mongoose.connection.readyState === 1) {
    await LoginEvent.create(event);
  }
}

async function createAlert(request, user, level, title, detail) {
  if (mongoose.connection.readyState !== 1) return;
  await SecurityAlert.create({
    userId: user?._id,
    level,
    title,
    detail,
    ip: getClientIp(request),
    userAgent: request.headers["user-agent"] || "unknown"
  });
}

function buildEmailTemplate({ name, otp, purpose }) {
  const label = purpose === "reset" ? "Password Reset" : purpose === "signup" ? "Account Verification" : "Login Verification";
  return `
    <div style="margin:0;padding:32px;background:#0B1120;color:#E5F6FF;font-family:Inter,Arial,sans-serif">
      <div style="max-width:560px;margin:auto;border:1px solid rgba(0,245,212,.28);border-radius:24px;background:rgba(15,23,42,.86);overflow:hidden">
        <div style="padding:28px;background:linear-gradient(135deg,#00F5D4,#3B82F6,#7C3AED)">
          <h1 style="margin:0;color:white;font-size:28px">SecureU ${label}</h1>
        </div>
        <div style="padding:32px">
          <p style="color:#CBD5E1;font-size:16px">Hi ${name || "there"}, use this one-time passcode to continue your secure session.</p>
          <div style="margin:28px 0;padding:20px;border-radius:18px;background:#050816;text-align:center;border:1px solid rgba(0,245,212,.28)">
            <strong style="font-size:36px;letter-spacing:8px;color:#00F5D4">${otp}</strong>
          </div>
          <p style="color:#94A3B8">This OTP expires in 5 minutes. Never share it with anyone, including SecureU support.</p>
          <p style="color:#64748B;font-size:13px">If you did not request this code, reset your password and review active sessions immediately.</p>
        </div>
      </div>
    </div>`;
}

async function sendEmailOtp(user, otp, purpose) {
  if (!mailer) {
    console.log(`[dev-email] ${purpose} OTP for ${user.email}: ${otp}`);
    return { provider: "demo-email", demoOtp: otp };
  }
  await mailer.sendMail({
    from: process.env.EMAIL_FROM,
    to: user.email,
    subject: `SecureU ${purpose} OTP`,
    html: buildEmailTemplate({ name: user.name, otp, purpose })
  });
  return { provider: "email" };
}

async function sendWhatsAppOtp(user, otp, purpose) {
  const message = `SecureU ${purpose} OTP: ${otp}. Valid for 5 minutes. Do not share this code.`;
  if (!whatsAppClient || !user.phone) {
    console.log(`[dev-whatsapp] ${purpose} OTP for ${user.phone || user.email}: ${otp}`);
    return { provider: "demo-whatsapp", demoOtp: otp };
  }
  try {
    await whatsAppClient.messages.create({
      from: process.env.TWILIO_WHATSAPP_FROM,
      to: `whatsapp:${user.phone}`,
      body: message
    });
    return { provider: "whatsapp" };
  } catch (error) {
    if (process.env.TWILIO_SMS_FROM && user.phone) {
      await whatsAppClient.messages.create({
        from: process.env.TWILIO_SMS_FROM,
        to: user.phone,
        body: message
      });
      return { provider: "sms-fallback" };
    }
    throw error;
  }
}

async function issueOtp({ request, response, user, purpose, channel }) {
  const resendLock = await cacheGet(resendKey(user._id, purpose));
  if (resendLock) {
    response.status(429);
    throw new Error(`Please wait ${resendLock.waitSeconds || OTP_RESEND_SECONDS} seconds before requesting another OTP.`);
  }

  const otp = generateOtp();
  await cacheSet(
    otpKey(user._id, purpose),
    {
      hash: hashOtp(otp),
      channel,
      purpose,
      attempts: 0,
      issuedAt: Date.now(),
      expiresAt: Date.now() + OTP_EXPIRES_SECONDS * 1000
    },
    OTP_EXPIRES_SECONDS
  );
  await cacheSet(resendKey(user._id, purpose), { waitSeconds: OTP_RESEND_SECONDS }, OTP_RESEND_SECONDS);

  const delivery = channel === "whatsapp" ? await sendWhatsAppOtp(user, otp, purpose) : await sendEmailOtp(user, otp, purpose);
  await trackEvent(request, user, "otp_sent", `${purpose} OTP sent using ${delivery.provider}.`, channel);

  return {
    message: `OTP sent through ${delivery.provider}.`,
    expiresIn: OTP_EXPIRES_SECONDS,
    resendAfter: OTP_RESEND_SECONDS,
    channel,
    purpose,
    demoOtp: delivery.demoOtp,
    user: { email: user.email, phone: user.phone ? maskPhone(user.phone) : null }
  };
}

function maskPhone(phone) {
  const value = String(phone);
  return value.length <= 4 ? "****" : `${"*".repeat(Math.max(0, value.length - 4))}${value.slice(-4)}`;
}

async function verifyOtp({ request, user, purpose, otp }) {
  const key = otpKey(user._id, purpose);
  const entry = await cacheGet(key);
  if (!entry) {
    await createAlert(request, user, "warning", "Expired OTP attempt", `Expired or missing OTP used for ${purpose}.`);
    throw Object.assign(new Error("Invalid or expired OTP."), { statusCode: 401 });
  }
  if (entry.attempts >= 5) {
    await cacheDelete(key);
    await createAlert(request, user, "critical", "OTP brute-force blocked", `Too many OTP attempts for ${purpose}.`);
    throw Object.assign(new Error("Too many OTP attempts. Request a new code."), { statusCode: 429 });
  }
  if (entry.hash !== hashOtp(otp)) {
    entry.attempts += 1;
    await cacheSet(key, entry, Math.max(1, Math.floor((entry.expiresAt - Date.now()) / 1000)));
    throw Object.assign(new Error("Incorrect OTP."), { statusCode: 401 });
  }
  await cacheDelete(key);
  return entry;
}

function signJwt(user, tokenId) {
  return jwt.sign(
    {
      sub: String(user._id),
      email: user.email,
      role: user.role,
      tokenId
    },
    JWT_SECRET,
    { expiresIn: process.env.JWT_EXPIRES_IN || "15m", issuer: "secureu-zero-trust" }
  );
}

async function createSession(request, response, user) {
  const tokenId = crypto.randomUUID();
  const deviceId = getDeviceId(request, response);
  const session = {
    userId: user._id,
    tokenId,
    deviceId,
    ip: getClientIp(request),
    userAgent: request.headers["user-agent"] || "unknown",
    lastSeenAt: new Date(),
    expiresAt: new Date(Date.now() + SESSION_EXPIRES_SECONDS * 1000)
  };
  if (mongoose.connection.readyState === 1) {
    await Session.create(session);
  } else {
    memorySessions.set(tokenId, session);
  }
  const token = signJwt(user, tokenId);
  response.cookie("auth_token", token, {
    httpOnly: true,
    sameSite: "strict",
    secure: IS_PRODUCTION,
    maxAge: SESSION_EXPIRES_SECONDS * 1000
  });
  return { tokenId, token };
}

async function requireAuth(request, response, next) {
  try {
    const token = request.cookies.auth_token || request.headers.authorization?.replace(/^Bearer\s+/i, "");
    if (!token) return response.status(401).json({ error: "Authentication required." });
    const payload = jwt.verify(token, JWT_SECRET, { issuer: "secureu-zero-trust" });
    const user = await findUserById(payload.sub);
    if (!user) return response.status(401).json({ error: "Invalid session." });

    let activeSession = null;
    if (mongoose.connection.readyState === 1) {
      activeSession = await Session.findOne({ tokenId: payload.tokenId, revokedAt: null, expiresAt: { $gt: new Date() } });
      if (activeSession) {
        activeSession.lastSeenAt = new Date();
        await activeSession.save();
      }
    } else {
      activeSession = memorySessions.get(payload.tokenId);
    }
    if (!activeSession) return response.status(401).json({ error: "Session expired or revoked." });

    request.user = user;
    request.auth = payload;
    request.sessionRecord = activeSession;
    next();
  } catch {
    response.status(401).json({ error: "Invalid or expired token." });
  }
}

function asyncHandler(handler) {
  return (request, response, next) => Promise.resolve(handler(request, response, next)).catch(next);
}

async function connectInfrastructure() {
  requireEnv("MONGODB_URI");
  requireEnv("JWT_SECRET");
  requireEnv("OTP_SECRET");

  if (process.env.MONGODB_URI) {
    await mongoose.connect(process.env.MONGODB_URI);
    console.log("MongoDB connected.");
  } else {
    console.warn("MONGODB_URI not set. Auth data will not persist across restarts.");
  }

  if (process.env.REDIS_URL) {
    redisClient = createClient({ url: process.env.REDIS_URL });
    redisClient.on("error", (error) => console.warn(`Redis error: ${error.message}`));
    await redisClient.connect();
    console.log("Redis connected.");
  } else {
    console.warn("REDIS_URL not set. OTP/session cache is using memory fallback.");
  }

  if (process.env.SMTP_HOST && process.env.SMTP_USER && process.env.SMTP_PASS) {
    mailer = nodemailer.createTransport({
      host: process.env.SMTP_HOST,
      port: Number(process.env.SMTP_PORT || 587),
      secure: Number(process.env.SMTP_PORT) === 465,
      auth: {
        user: process.env.SMTP_USER,
        pass: process.env.SMTP_PASS
      }
    });
  }

  if (process.env.TWILIO_ACCOUNT_SID && process.env.TWILIO_AUTH_TOKEN) {
    whatsAppClient = twilio(process.env.TWILIO_ACCOUNT_SID, process.env.TWILIO_AUTH_TOKEN);
  }

  await seedInitialUser();
}

app.set("trust proxy", 1);
app.use(
  helmet({
    contentSecurityPolicy: {
      directives: {
        defaultSrc: ["'self'"],
        scriptSrc: ["'self'"],
        styleSrc: ["'self'", "https://fonts.googleapis.com", "'unsafe-inline'"],
        fontSrc: ["'self'", "https://fonts.gstatic.com"],
        imgSrc: ["'self'", "data:"],
        connectSrc: ["'self'"],
        frameAncestors: ["'none'"]
      }
    }
  })
);
app.use((request, response, next) => {
  if (IS_PRODUCTION && request.headers["x-forwarded-proto"] && request.headers["x-forwarded-proto"] !== "https") {
    return response.redirect(301, `https://${request.headers.host}${request.originalUrl}`);
  }
  next();
});
app.use(compression());
app.use(express.json({ limit: "32kb" }));
app.use(express.urlencoded({ extended: false, limit: "32kb" }));
app.use(cookieParser());
app.use(mongoSanitize());
app.use(xss());
app.use(hpp());

const allowedOrigins = (process.env.ALLOWED_ORIGINS || PUBLIC_APP_URL).split(",").map((origin) => origin.trim());
app.use(
  cors({
    origin(origin, callback) {
      if (!origin || allowedOrigins.includes(origin)) return callback(null, true);
      return callback(new Error("Origin not allowed."));
    },
    credentials: true
  })
);

app.use("/api", async (request, response, next) => {
  try {
    if (!infrastructureReady) infrastructureReady = connectInfrastructure();
    await infrastructureReady;
    next();
  } catch (error) {
    next(error);
  }
});

const csrfProtection = csrf({
  cookie: {
    httpOnly: true,
    sameSite: "strict",
    secure: IS_PRODUCTION
  }
});

const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 40,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: "Too many authentication attempts. Try again later." }
});

const otpLimiter = rateLimit({
  windowMs: 60 * 1000,
  limit: 6,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: "Too many OTP requests. Slow down and try again." }
});

app.get("/api/csrf-token", csrfProtection, (request, response) => {
  response.json({ csrfToken: request.csrfToken() });
});

app.post(
  "/api/auth/signup",
  authLimiter,
  csrfProtection,
  asyncHandler(async (request, response) => {
    const { name, email, phone, password, channel = "email" } = request.body;
    const normalizedEmail = normalizeEmail(email);
    if (!name || !normalizedEmail || !password || password.length < 8) {
      return response.status(400).json({ error: "Name, valid email, and password of at least 8 characters are required." });
    }
    const existing = await findUserByEmail(normalizedEmail);
    if (existing) return response.status(409).json({ error: "An account already exists for this email." });

    const passwordHash = await bcrypt.hash(password, 12);
    const user = await createUser({ name, email: normalizedEmail, phone, passwordHash, role: "employee" });
    const payload = await issueOtp({ request, response, user, purpose: "signup", channel: normalizeChannel(channel) });
    response.status(201).json(payload);
  })
);

app.post(
  "/api/auth/login",
  authLimiter,
  csrfProtection,
  asyncHandler(async (request, response) => {
    const { email, password, channel = "email" } = request.body;
    const user = await findUserByEmail(email);
    if (!user || !(await bcrypt.compare(String(password || ""), user.passwordHash))) {
      await trackEvent(request, user, "failed", "Invalid email or password.", normalizeChannel(channel));
      if (user) {
        user.failedLoginCount += 1;
        await user.save();
        if (user.failedLoginCount >= 5) {
          await createAlert(request, user, "critical", "Brute-force pattern detected", "Multiple failed password attempts detected.");
        }
      }
      return response.status(401).json({ error: "Invalid credentials." });
    }
    const payload = await issueOtp({ request, response, user, purpose: "login", channel: normalizeChannel(channel) });
    response.json(payload);
  })
);

app.post(
  "/api/auth/otp/resend",
  otpLimiter,
  csrfProtection,
  asyncHandler(async (request, response) => {
    const { email, purpose = "login", channel = "email" } = request.body;
    const user = await findUserByEmail(email);
    if (!user) return response.status(404).json({ error: "Account not found." });
    const payload = await issueOtp({ request, response, user, purpose, channel: normalizeChannel(channel) });
    response.json(payload);
  })
);

app.post(
  "/api/auth/otp/verify",
  otpLimiter,
  csrfProtection,
  asyncHandler(async (request, response) => {
    const { email, otp, purpose = "login" } = request.body;
    const user = await findUserByEmail(email);
    if (!user) return response.status(404).json({ error: "Account not found." });
    const entry = await verifyOtp({ request, user, purpose, otp });

    if (purpose === "signup") {
      if (entry.channel === "whatsapp") user.isWhatsAppVerified = true;
      else user.isEmailVerified = true;
    }
    user.failedLoginCount = 0;
    user.lastLoginAt = new Date();
    await user.save();
    await trackEvent(request, user, "otp_verified", `${purpose} OTP verified.`, entry.channel);

    if (purpose === "reset") {
      const resetToken = crypto.randomBytes(32).toString("hex");
      await cacheSet(resetKey(resetToken), { userId: String(user._id) }, 10 * 60);
      return response.json({ message: "OTP verified. Continue to reset password.", resetToken, redirectTo: "/reset-password.html" });
    }

    const session = await createSession(request, response, user);
    response.json({
      message: "OTP verified. Secure session established.",
      user: publicUser(user),
      token: session.token,
      redirectTo: "/dashboard.html"
    });
  })
);

app.post(
  "/api/auth/forgot-password",
  authLimiter,
  csrfProtection,
  asyncHandler(async (request, response) => {
    const { email, channel = "email" } = request.body;
    const user = await findUserByEmail(email);
    if (!user) {
      return response.json({ message: "If the account exists, a reset OTP has been sent.", expiresIn: OTP_EXPIRES_SECONDS, resendAfter: OTP_RESEND_SECONDS });
    }
    const payload = await issueOtp({ request, response, user, purpose: "reset", channel: normalizeChannel(channel) });
    response.json(payload);
  })
);

app.post(
  "/api/auth/reset-password",
  authLimiter,
  csrfProtection,
  asyncHandler(async (request, response) => {
    const { resetToken, password } = request.body;
    if (!resetToken || !password || password.length < 8) return response.status(400).json({ error: "Reset token and stronger password are required." });
    const reset = await cacheGet(resetKey(resetToken));
    if (!reset) return response.status(401).json({ error: "Reset token expired. Request a new OTP." });
    const user = await findUserById(reset.userId);
    if (!user) return response.status(404).json({ error: "Account not found." });
    user.passwordHash = await bcrypt.hash(password, 12);
    user.failedLoginCount = 0;
    await user.save();
    await cacheDelete(resetKey(resetToken));
    await trackEvent(request, user, "reset", "Password reset completed.", "email");
    await createAlert(request, user, "info", "Password changed", "Account password was reset after OTP verification.");
    response.json({ message: "Password reset complete. You can sign in now.", redirectTo: "/login.html" });
  })
);

app.post(
  "/api/auth/logout",
  csrfProtection,
  requireAuth,
  asyncHandler(async (request, response) => {
    if (mongoose.connection.readyState === 1) {
      await Session.updateOne({ tokenId: request.auth.tokenId }, { revokedAt: new Date() });
    } else {
      memorySessions.delete(request.auth.tokenId);
    }
    await trackEvent(request, request.user, "logout", "User signed out.", "session");
    response.clearCookie("auth_token");
    response.json({ message: "Signed out." });
  })
);

app.get(
  "/api/auth/me",
  requireAuth,
  asyncHandler(async (request, response) => {
    response.json({ user: publicUser(request.user), session: request.sessionRecord });
  })
);

app.get(
  "/api/security/dashboard",
  requireAuth,
  asyncHandler(async (request, response) => {
    if (mongoose.connection.readyState !== 1) {
      return response.json({
        loginHistory: [],
        activeSessions: Array.from(memorySessions.values()).filter((session) => String(session.userId) === String(request.user._id)),
        securityAlerts: [],
        otpAnalytics: { totalOtpRequests: 0, emailRequests: 0, whatsAppRequests: 0 }
      });
    }
    const [loginHistory, activeSessions, securityAlerts, otpEvents] = await Promise.all([
      LoginEvent.find({ userId: request.user._id }).sort({ createdAt: -1 }).limit(20),
      Session.find({ userId: request.user._id, revokedAt: null, expiresAt: { $gt: new Date() } }).sort({ lastSeenAt: -1 }).limit(20),
      SecurityAlert.find({ userId: request.user._id }).sort({ createdAt: -1 }).limit(20),
      LoginEvent.find({ userId: request.user._id, status: "otp_sent" })
    ]);
    response.json({
      loginHistory,
      activeSessions,
      securityAlerts,
      otpAnalytics: {
        totalOtpRequests: otpEvents.length,
        emailRequests: otpEvents.filter((event) => event.channel === "email").length,
        whatsAppRequests: otpEvents.filter((event) => event.channel === "whatsapp").length
      }
    });
  })
);

// Compatibility routes for the original demo endpoints.
app.get("/api/session", requireAuth, (request, response) => {
  response.json({ authenticated: true, otpVerified: true, user: publicUser(request.user) });
});

app.get("/api/access", requireAuth, (request, response) => {
  response.json({
    message: "Access evaluated with zero-trust checks.",
    role: request.user.role,
    section: roleContent[request.user.role] || roleContent.employee
  });
});

app.use(express.static(path.join(__dirname, "public"), { extensions: ["html"] }));
app.get("*", (request, response) => {
  response.sendFile(path.join(__dirname, "public", "index.html"));
});

app.use((error, request, response, next) => {
  if (error.code === "EBADCSRFTOKEN") {
    return response.status(403).json({ error: "Invalid CSRF token. Refresh and try again." });
  }
  const statusCode = error.statusCode || response.statusCode || 500;
  response.status(statusCode >= 400 ? statusCode : 500).json({ error: error.message || "Internal server error." });
});

if (require.main === module) {
  infrastructureReady = connectInfrastructure();
  infrastructureReady
    .then(() => {
      app.listen(PORT, () => {
        console.log(`SecureU Zero Trust server running on ${PUBLIC_APP_URL}`);
      });
    })
    .catch((error) => {
      console.error("Failed to start server:", error);
      process.exit(1);
    });
} else {
  infrastructureReady = connectInfrastructure();
}

module.exports = app;
