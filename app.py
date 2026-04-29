import json
import os
import secrets
from datetime import datetime, timezone
from http import HTTPStatus
from http.cookies import SimpleCookie
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path


HOST = os.environ.get("HOST", "0.0.0.0")
PORT = int(os.environ.get("PORT", "3000"))
BASE_DIR = Path(__file__).resolve().parent
PUBLIC_DIR = BASE_DIR / "public"

USERS = {
    "admin": {
        "username": "admin",
        "password": "Admin@123",
        "role": "admin",
        "name": "Primary Administrator",
    },
    "employee": {
        "username": "employee",
        "password": "Employee@123",
        "role": "employee",
        "name": "Operations Employee",
    },
    "guest": {
        "username": "guest",
        "password": "Guest@123",
        "role": "guest",
        "name": "Visitor Guest",
    },
}

ROLE_CONTENT = {
    "admin": {
        "title": "Admin Control Center",
        "items": [
            "Approve or block sensitive access requests",
            "Review live OTP issuance metrics",
            "Audit role-based policy decisions",
        ],
    },
    "employee": {
        "title": "Employee Workspace",
        "items": [
            "View assigned internal resources",
            "Confirm device trust before access",
            "Request temporary elevated permissions",
        ],
    },
    "guest": {
        "title": "Guest Access Portal",
        "items": [
            "Use time-limited visitor access",
            "Enter shared meeting resources only",
            "Stay isolated from internal admin systems",
        ],
    },
}

SESSIONS = {}
LOGIN_EVENTS = []


def utc_now():
    return datetime.now(timezone.utc).isoformat()


def summarize_os(user_agent):
    agent = user_agent.lower()
    if "windows" in agent:
        return "Windows"
    if "mac os" in agent or "macintosh" in agent:
        return "macOS"
    if "android" in agent:
        return "Android"
    if "iphone" in agent or "ipad" in agent or "ios" in agent:
        return "iOS"
    if "linux" in agent:
        return "Linux"
    return "Unknown OS"


def summarize_browser(user_agent):
    agent = user_agent.lower()
    if "edg/" in agent:
        return "Microsoft Edge"
    if "chrome/" in agent and "edg/" not in agent:
        return "Google Chrome"
    if "firefox/" in agent:
        return "Mozilla Firefox"
    if "safari/" in agent and "chrome/" not in agent:
        return "Safari"
    return "Unknown Browser"


def summarize_device_type(user_agent):
    agent = user_agent.lower()
    if "ipad" in agent or "tablet" in agent:
        return "Tablet"
    if "mobile" in agent or "android" in agent or "iphone" in agent:
        return "Mobile Device"
    return "Desktop"


def get_client_ip(handler):
    forwarded_for = handler.headers.get("X-Forwarded-For", "")
    if forwarded_for:
        return forwarded_for.split(",")[0].strip()
    return handler.client_address[0]


def build_trust_context(user, handler):
    user_agent = handler.headers.get("User-Agent", "Unknown Agent")
    ip_address = get_client_ip(handler)
    device_type = summarize_device_type(user_agent)
    browser = summarize_browser(user_agent)
    operating_system = summarize_os(user_agent)
    private_network = (
        ip_address.startswith("127.")
        or ip_address.startswith("10.")
        or ip_address.startswith("192.168.")
        or ip_address.startswith("172.16.")
    )

    score = 55
    reasons = []

    if private_network:
        score += 20
        reasons.append("Trusted network range detected")
    else:
        reasons.append("External network address detected")

    if device_type == "Desktop":
        score += 10
        reasons.append("Desktop device profile is considered lower risk")
    else:
        reasons.append("Non-desktop device requires closer review")

    if user["role"] == "admin":
        score -= 5
        reasons.append("Admin sessions require stricter scrutiny")
    elif user["role"] == "guest":
        score -= 10
        reasons.append("Guest role stays restricted by design")
    else:
        score += 5
        reasons.append("Employee role matches standard access policy")

    score = max(0, min(100, score))

    if score >= 75:
        status = "Trusted"
        decision = "Full role access granted after OTP verification."
    elif score >= 60:
        status = "Elevated Review"
        decision = "Access granted with monitoring and step-up scrutiny."
    else:
        status = "Restricted"
        decision = "Access granted only to the minimum role scope."

    return {
        "ip_address": ip_address,
        "user_agent": user_agent,
        "device_type": device_type,
        "browser": browser,
        "operating_system": operating_system,
        "network_zone": "Private Network" if private_network else "External Network",
        "trust_score": score,
        "trust_status": status,
        "policy_decision": decision,
        "reasons": reasons,
    }


def session_user_payload(session):
    return {
        "username": session["username"],
        "name": session["name"],
        "role": session["role"],
    }


def session_context_payload(session):
    return {
        "createdAt": session["created_at"],
        "lastSeenAt": session["last_seen_at"],
        "otpIssuedAt": session["otp_issued_at"],
        "otpUsageCount": session["otp_usage_count"],
        "trust": {
            "ipAddress": session["trust_context"]["ip_address"],
            "userAgent": session["trust_context"]["user_agent"],
            "deviceType": session["trust_context"]["device_type"],
            "browser": session["trust_context"]["browser"],
            "operatingSystem": session["trust_context"]["operating_system"],
            "networkZone": session["trust_context"]["network_zone"],
            "score": session["trust_context"]["trust_score"],
            "status": session["trust_context"]["trust_status"],
            "policyDecision": session["trust_context"]["policy_decision"],
            "reasons": session["trust_context"]["reasons"],
        },
    }


def record_login_event(session, event_type):
    LOGIN_EVENTS.insert(
        0,
        {
            "timestamp": utc_now(),
            "eventType": event_type,
            "username": session["username"],
            "name": session["name"],
            "role": session["role"],
            "ipAddress": session["trust_context"]["ip_address"],
            "deviceType": session["trust_context"]["device_type"],
            "browser": session["trust_context"]["browser"],
            "trustStatus": session["trust_context"]["trust_status"],
            "trustScore": session["trust_context"]["trust_score"],
        },
    )
    del LOGIN_EVENTS[50:]


def new_session(user):
    session_id = secrets.token_hex(24)
    timestamp = utc_now()
    session = {
        "session_id": session_id,
        "username": user["username"],
        "name": user["name"],
        "role": user["role"],
        "otp_verified": False,
        "otp": None,
        "otp_issued_at": None,
        "otp_usage_count": 0,
        "created_at": timestamp,
        "last_seen_at": timestamp,
        "trust_context": None,
    }
    SESSIONS[session_id] = session
    return session


def generate_otp(previous_otp=None):
    otp = ""
    while len(otp) != 6 or otp == previous_otp:
        otp = f"{secrets.randbelow(900000) + 100000}"
    return otp


def issue_otp(session):
    otp = generate_otp(session["otp"])
    session["otp"] = otp
    session["otp_verified"] = False
    session["otp_issued_at"] = utc_now()
    session["otp_usage_count"] += 1
    return otp


class ZeroTrustHandler(BaseHTTPRequestHandler):
    server_version = "ZeroTrustDemo/1.0"

    def do_GET(self):
        if self.path.startswith("/api/"):
            self.handle_api()
            return
        self.serve_static()

    def do_POST(self):
        if self.path.startswith("/api/"):
            self.handle_api()
            return
        self.send_json(HTTPStatus.NOT_FOUND, {"error": "Endpoint not found."})

    def handle_api(self):
        try:
            if self.command == "POST" and self.path == "/api/login":
                body = self.read_json()
                user = USERS.get(body.get("username"))
                if not user or user["password"] != body.get("password"):
                    self.send_json(HTTPStatus.UNAUTHORIZED, {"error": "Invalid credentials."})
                    return

                session = new_session(user)
                session["trust_context"] = build_trust_context(user, self)
                otp = issue_otp(session)
                record_login_event(session, "login-issued")
                self.send_json(
                    HTTPStatus.OK,
                    {
                        "message": "Login accepted. Verify the fresh OTP to continue.",
                        "otp": otp,
                        "role": session["role"],
                        "name": session["name"],
                        "context": session_context_payload(session),
                    },
                    cookie=f"sid={session['session_id']}; HttpOnly; SameSite=Strict; Path=/",
                )
                return

            if self.command == "POST" and self.path == "/api/otp/regenerate":
                session = self.require_session()
                if not session:
                    return

                otp = issue_otp(session)
                self.send_json(
                    HTTPStatus.OK,
                    {
                        "message": "A different OTP has been generated.",
                        "otp": otp,
                        "issuedAt": session["otp_issued_at"],
                        "otpUsageCount": session["otp_usage_count"],
                        "context": session_context_payload(session),
                    },
                )
                return

            if self.command == "POST" and self.path == "/api/otp/verify":
                session = self.require_session()
                if not session:
                    return

                body = self.read_json()
                if body.get("otp") != session.get("otp"):
                    self.send_json(HTTPStatus.UNAUTHORIZED, {"error": "Incorrect OTP."})
                    return

                session["otp_verified"] = True
                session["otp"] = None
                record_login_event(session, "otp-verified")
                self.send_json(
                    HTTPStatus.OK,
                    {
                        "message": "OTP verified. Access granted by role.",
                        "user": session_user_payload(session),
                        "context": session_context_payload(session),
                    },
                )
                return

            if self.command == "POST" and self.path == "/api/logout":
                session = self.get_session()
                if session:
                    SESSIONS.pop(session["session_id"], None)

                self.send_json(
                    HTTPStatus.OK,
                    {"message": "Signed out."},
                    cookie="sid=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0",
                )
                return

            if self.command == "GET" and self.path == "/api/session":
                session = self.get_session()
                self.send_json(
                    HTTPStatus.OK,
                    {
                        "authenticated": bool(session),
                        "otpVerified": bool(session and session["otp_verified"]),
                        "user": session_user_payload(session) if session else None,
                        "context": session_context_payload(session) if session else None,
                    },
                )
                return

            if self.command == "GET" and self.path == "/api/access":
                session = self.require_verified_session()
                if not session:
                    return

                if session["role"] == "admin":
                    sections = {
                        "admin": ROLE_CONTENT["admin"],
                        "employee": ROLE_CONTENT["employee"],
                        "guest": ROLE_CONTENT["guest"],
                    }
                else:
                    sections = {session["role"]: ROLE_CONTENT[session["role"]]}

                self.send_json(
                    HTTPStatus.OK,
                    {
                        "message": "Access evaluated with zero-trust checks.",
                        "role": session["role"],
                        "section": ROLE_CONTENT[session["role"]],
                        "sections": sections,
                        "context": session_context_payload(session),
                    },
                )
                return

            if self.command == "GET" and self.path == "/api/admin/activity":
                session = self.require_verified_session()
                if not session:
                    return
                if session["role"] != "admin":
                    self.send_json(HTTPStatus.FORBIDDEN, {"error": "Admin access required."})
                    return

                self.send_json(
                    HTTPStatus.OK,
                    {
                        "events": LOGIN_EVENTS,
                    },
                )
                return

            self.send_json(HTTPStatus.NOT_FOUND, {"error": "Endpoint not found."})
        except json.JSONDecodeError:
            self.send_json(HTTPStatus.BAD_REQUEST, {"error": "Invalid JSON body."})
        except Exception as error:
            self.send_json(HTTPStatus.INTERNAL_SERVER_ERROR, {"error": str(error)})

    def require_session(self):
        session = self.get_session()
        if not session:
            self.send_json(HTTPStatus.UNAUTHORIZED, {"error": "Sign in first."})
            return None
        session["last_seen_at"] = utc_now()
        return session

    def require_verified_session(self):
        session = self.require_session()
        if not session:
            return None
        if not session["otp_verified"]:
            self.send_json(HTTPStatus.FORBIDDEN, {"error": "OTP verification required."})
            return None
        return session

    def get_session(self):
        cookie_header = self.headers.get("Cookie")
        if not cookie_header:
            return None

        cookie = SimpleCookie()
        cookie.load(cookie_header)
        morsel = cookie.get("sid")
        if not morsel:
            return None
        return SESSIONS.get(morsel.value)

    def read_json(self):
        length = int(self.headers.get("Content-Length", "0"))
        raw = self.rfile.read(length) if length else b"{}"
        return json.loads(raw.decode("utf-8"))

    def serve_static(self):
        relative = self.path.split("?", 1)[0]
        if relative == "/":
            relative = "/index.html"

        safe_relative = relative.lstrip("/")
        file_path = (PUBLIC_DIR / safe_relative).resolve()
        public_root = PUBLIC_DIR.resolve()

        if public_root not in file_path.parents and file_path != public_root:
            self.send_json(HTTPStatus.FORBIDDEN, {"error": "Forbidden path."})
            return

        if not file_path.exists() or file_path.is_dir():
            self.send_json(HTTPStatus.NOT_FOUND, {"error": "File not found."})
            return

        content_type = {
            ".html": "text/html; charset=utf-8",
            ".css": "text/css; charset=utf-8",
            ".js": "application/javascript; charset=utf-8",
        }.get(file_path.suffix, "text/plain; charset=utf-8")

        self.send_response(HTTPStatus.OK)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(file_path.stat().st_size))
        self.end_headers()
        self.wfile.write(file_path.read_bytes())

    def send_json(self, status, payload, cookie=None):
        body = json.dumps(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        if cookie:
            self.send_header("Set-Cookie", cookie)
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format_string, *args):
        return


if __name__ == "__main__":
    server = ThreadingHTTPServer((HOST, PORT), ZeroTrustHandler)
    print(f"Zero trust security tool running on http://{HOST}:{PORT}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
