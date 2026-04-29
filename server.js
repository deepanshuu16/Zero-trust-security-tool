const http = require("http");
const fs = require("fs");
const path = require("path");
const crypto = require("crypto");

const PORT = process.env.PORT || 3000;

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
    title: "Admin Control Center",
    items: [
      "Approve or block sensitive access requests",
      "Review live OTP issuance metrics",
      "Audit role-based policy decisions"
    ]
  },
  employee: {
    title: "Employee Workspace",
    items: [
      "View assigned internal resources",
      "Confirm device trust before access",
      "Request temporary elevated permissions"
    ]
  },
  guest: {
    title: "Guest Access Portal",
    items: [
      "Use time-limited visitor access",
      "Enter shared meeting resources only",
      "Stay isolated from internal admin systems"
    ]
  }
};

const sessions = new Map();

function sendJson(response, statusCode, payload) {
  response.writeHead(statusCode, { "Content-Type": "application/json; charset=utf-8" });
  response.end(JSON.stringify(payload));
}

function parseBody(request) {
  return new Promise((resolve, reject) => {
    let data = "";
    request.on("data", (chunk) => {
      data += chunk;
      if (data.length > 1e6) {
        reject(new Error("Request body too large"));
      }
    });
    request.on("end", () => {
      if (!data) {
        resolve({});
        return;
      }
      try {
        resolve(JSON.parse(data));
      } catch (error) {
        reject(new Error("Invalid JSON body"));
      }
    });
    request.on("error", reject);
  });
}

function parseCookies(request) {
  const cookieHeader = request.headers.cookie || "";
  return cookieHeader.split(";").reduce((accumulator, item) => {
    const [key, ...rest] = item.trim().split("=");
    if (!key) {
      return accumulator;
    }
    accumulator[key] = decodeURIComponent(rest.join("="));
    return accumulator;
  }, {});
}

function createSession(user) {
  const sessionId = crypto.randomUUID();
  const session = {
    sessionId,
    username: user.username,
    name: user.name,
    role: user.role,
    otpVerified: false,
    otp: null,
    otpIssuedAt: null,
    otpUsageCount: 0
  };

  sessions.set(sessionId, session);
  return session;
}

function getSession(request) {
  const cookies = parseCookies(request);
  const sessionId = cookies.sid;
  if (!sessionId) {
    return null;
  }
  return sessions.get(sessionId) || null;
}

function generateOtp(previousOtp) {
  let nextOtp = "";
  do {
    nextOtp = crypto.randomInt(100000, 1000000).toString();
  } while (nextOtp === previousOtp);
  return nextOtp;
}

function issueOtp(session) {
  const otp = generateOtp(session.otp);
  session.otp = otp;
  session.otpVerified = false;
  session.otpIssuedAt = new Date().toISOString();
  session.otpUsageCount += 1;
  return otp;
}

function requireSession(request, response) {
  const session = getSession(request);
  if (!session) {
    sendJson(response, 401, { error: "Sign in first." });
    return null;
  }
  return session;
}

function requireVerifiedSession(request, response) {
  const session = requireSession(request, response);
  if (!session) {
    return null;
  }
  if (!session.otpVerified) {
    sendJson(response, 403, { error: "OTP verification required." });
    return null;
  }
  return session;
}

function serveFile(response, filePath) {
  fs.readFile(filePath, (error, data) => {
    if (error) {
      sendJson(response, 404, { error: "File not found." });
      return;
    }

    const extension = path.extname(filePath);
    const contentTypes = {
      ".html": "text/html; charset=utf-8",
      ".css": "text/css; charset=utf-8",
      ".js": "application/javascript; charset=utf-8"
    };

    response.writeHead(200, { "Content-Type": contentTypes[extension] || "text/plain; charset=utf-8" });
    response.end(data);
  });
}

async function handleApi(request, response) {
  if (request.method === "POST" && request.url === "/api/login") {
    const body = await parseBody(request);
    const user = users[body.username];

    if (!user || user.password !== body.password) {
      sendJson(response, 401, { error: "Invalid credentials." });
      return;
    }

    const session = createSession(user);
    const otp = issueOtp(session);

    response.writeHead(200, {
      "Content-Type": "application/json; charset=utf-8",
      "Set-Cookie": `sid=${session.sessionId}; HttpOnly; SameSite=Strict; Path=/`
    });
    response.end(JSON.stringify({
      message: "Login accepted. Verify the fresh OTP to continue.",
      otp,
      role: session.role,
      name: session.name
    }));
    return;
  }

  if (request.method === "POST" && request.url === "/api/otp/regenerate") {
    const session = requireSession(request, response);
    if (!session) {
      return;
    }

    const otp = issueOtp(session);
    sendJson(response, 200, {
      message: "A different OTP has been generated.",
      otp,
      issuedAt: session.otpIssuedAt,
      otpUsageCount: session.otpUsageCount
    });
    return;
  }

  if (request.method === "POST" && request.url === "/api/otp/verify") {
    const session = requireSession(request, response);
    if (!session) {
      return;
    }

    const body = await parseBody(request);
    if (!session.otp || body.otp !== session.otp) {
      sendJson(response, 401, { error: "Incorrect OTP." });
      return;
    }

    session.otpVerified = true;
    session.otp = null;

    sendJson(response, 200, {
      message: "OTP verified. Access granted by role.",
      user: {
        username: session.username,
        name: session.name,
        role: session.role
      }
    });
    return;
  }

  if (request.method === "POST" && request.url === "/api/logout") {
    const session = getSession(request);
    if (session) {
      sessions.delete(session.sessionId);
    }

    response.writeHead(200, {
      "Content-Type": "application/json; charset=utf-8",
      "Set-Cookie": "sid=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0"
    });
    response.end(JSON.stringify({ message: "Signed out." }));
    return;
  }

  if (request.method === "GET" && request.url === "/api/session") {
    const session = getSession(request);
    sendJson(response, 200, {
      authenticated: Boolean(session),
      otpVerified: Boolean(session && session.otpVerified),
      user: session
        ? {
            username: session.username,
            name: session.name,
            role: session.role
          }
        : null
    });
    return;
  }

  if (request.method === "GET" && request.url === "/api/access") {
    const session = requireVerifiedSession(request, response);
    if (!session) {
      return;
    }

    sendJson(response, 200, {
      message: "Access evaluated with zero-trust checks.",
      role: session.role,
      section: roleContent[session.role]
    });
    return;
  }

  sendJson(response, 404, { error: "Endpoint not found." });
}

const server = http.createServer(async (request, response) => {
  try {
    if (request.url.startsWith("/api/")) {
      await handleApi(request, response);
      return;
    }

    const publicDir = path.join(__dirname, "public");
    const requestedPath = request.url === "/" ? "/index.html" : request.url;
    const safePath = path.normalize(requestedPath).replace(/^(\.\.[/\\])+/, "");
    serveFile(response, path.join(publicDir, safePath));
  } catch (error) {
    sendJson(response, 500, { error: error.message || "Internal server error." });
  }
});

server.listen(PORT, () => {
  console.log(`Zero trust security tool running on http://localhost:${PORT}`);
});
