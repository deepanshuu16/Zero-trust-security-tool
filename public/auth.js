const authStateKey = "secureu-auth-flow";

function authState() {
  try {
    return JSON.parse(sessionStorage.getItem(authStateKey)) || {};
  } catch {
    return {};
  }
}

function saveAuthState(nextState) {
  sessionStorage.setItem(authStateKey, JSON.stringify({ ...authState(), ...nextState }));
}

async function csrfToken() {
  const cached = authState().csrfToken;
  if (cached) return cached;
  const response = await fetch("/api/csrf-token", { credentials: "include" });
  const data = await response.json();
  saveAuthState({ csrfToken: data.csrfToken });
  return data.csrfToken;
}

async function apiFetch(path, options = {}) {
  const token = await csrfToken();
  const response = await fetch(path, {
    credentials: "include",
    headers: {
      "Content-Type": "application/json",
      "CSRF-Token": token,
      ...(options.headers || {})
    },
    ...options,
    body: options.body ? JSON.stringify(options.body) : undefined
  });
  const data = await response.json().catch(() => ({}));
  if (!response.ok) {
    if (response.status === 403) saveAuthState({ csrfToken: null });
    throw new Error(data.error || "Request failed.");
  }
  return data;
}

function setLoading(form, loading) {
  const button = form?.querySelector("button[type='submit']");
  if (!button) return;
  button.disabled = loading;
  button.classList.toggle("is-loading", loading);
}

function showMessage(type, text) {
  const target = document.querySelector("[data-auth-message]");
  if (!target) return;
  target.className = `auth-message ${type}`;
  target.textContent = text || "";
}

function selectedChannel() {
  const selected = document.querySelector("input[name='channel']:checked");
  return selected?.value || "email";
}

function startResendTimer(seconds = 60) {
  const button = document.querySelector("[data-resend-otp]");
  const label = document.querySelector("[data-resend-timer]");
  if (!button || !label) return;
  let remaining = seconds;
  button.disabled = true;
  label.textContent = `${remaining}s`;
  const interval = window.setInterval(() => {
    remaining -= 1;
    label.textContent = `${Math.max(0, remaining)}s`;
    if (remaining <= 0) {
      window.clearInterval(interval);
      button.disabled = false;
      label.textContent = "ready";
    }
  }, 1000);
}

function initOtpInputs() {
  const inputs = Array.from(document.querySelectorAll(".otp-box"));
  if (!inputs.length) return;
  inputs[0].focus();
  inputs.forEach((input, index) => {
    input.addEventListener("input", () => {
      input.value = input.value.replace(/\D/g, "").slice(0, 1);
      if (input.value && inputs[index + 1]) inputs[index + 1].focus();
      updateOtpHidden(inputs);
    });
    input.addEventListener("keydown", (event) => {
      if (event.key === "Backspace" && !input.value && inputs[index - 1]) inputs[index - 1].focus();
    });
    input.addEventListener("paste", (event) => {
      event.preventDefault();
      const pasted = event.clipboardData.getData("text").replace(/\D/g, "").slice(0, inputs.length);
      pasted.split("").forEach((char, charIndex) => {
        if (inputs[charIndex]) inputs[charIndex].value = char;
      });
      updateOtpHidden(inputs);
      inputs[Math.min(pasted.length, inputs.length) - 1]?.focus();
    });
  });
}

function updateOtpHidden(inputs) {
  const hidden = document.getElementById("otp");
  if (hidden) hidden.value = inputs.map((input) => input.value).join("");
  const complete = hidden?.value.length === 6;
  document.querySelector("[data-otp-status]")?.classList.toggle("is-complete", complete);
}

function initAuthBackground() {
  const glow = document.querySelector(".mouse-glow");
  if (!glow) return;
  window.addEventListener("pointermove", (event) => {
    document.documentElement.style.setProperty("--cursor-x", `${event.clientX}px`);
    document.documentElement.style.setProperty("--cursor-y", `${event.clientY}px`);
  });
}

function initLogin() {
  const form = document.getElementById("auth-login-form");
  if (!form) return;
  form.addEventListener("submit", async (event) => {
    event.preventDefault();
    setLoading(form, true);
    showMessage("", "");
    const data = new FormData(form);
    try {
      const result = await apiFetch("/api/auth/login", {
        method: "POST",
        body: {
          email: data.get("email"),
          password: data.get("password"),
          channel: selectedChannel()
        }
      });
      saveAuthState({ email: data.get("email"), purpose: "login", channel: result.channel, resendAfter: result.resendAfter, demoOtp: result.demoOtp });
      window.location.href = "/verify-otp.html";
    } catch (error) {
      showMessage("error", error.message);
    } finally {
      setLoading(form, false);
    }
  });
}

function initSignup() {
  const form = document.getElementById("auth-signup-form");
  if (!form) return;
  form.addEventListener("submit", async (event) => {
    event.preventDefault();
    setLoading(form, true);
    showMessage("", "");
    const data = new FormData(form);
    try {
      const result = await apiFetch("/api/auth/signup", {
        method: "POST",
        body: {
          name: data.get("name"),
          email: data.get("email"),
          phone: data.get("phone"),
          password: data.get("password"),
          channel: selectedChannel()
        }
      });
      saveAuthState({ email: data.get("email"), purpose: "signup", channel: result.channel, resendAfter: result.resendAfter, demoOtp: result.demoOtp });
      window.location.href = "/verify-otp.html";
    } catch (error) {
      showMessage("error", error.message);
    } finally {
      setLoading(form, false);
    }
  });
}

function initForgotPassword() {
  const form = document.getElementById("auth-forgot-form");
  if (!form) return;
  form.addEventListener("submit", async (event) => {
    event.preventDefault();
    setLoading(form, true);
    showMessage("", "");
    const data = new FormData(form);
    try {
      const result = await apiFetch("/api/auth/forgot-password", {
        method: "POST",
        body: { email: data.get("email"), channel: selectedChannel() }
      });
      saveAuthState({ email: data.get("email"), purpose: "reset", channel: result.channel || selectedChannel(), resendAfter: result.resendAfter, demoOtp: result.demoOtp });
      window.location.href = "/verify-otp.html";
    } catch (error) {
      showMessage("error", error.message);
    } finally {
      setLoading(form, false);
    }
  });
}

function initVerifyOtp() {
  const form = document.getElementById("auth-otp-form");
  if (!form) return;
  const state = authState();
  document.querySelectorAll("[data-auth-email]").forEach((item) => {
    item.textContent = state.email || "your account";
  });
  document.querySelectorAll("[data-auth-channel]").forEach((item) => {
    item.textContent = state.channel || "email";
  });
  document.querySelectorAll("[data-demo-otp]").forEach((item) => {
    if (state.demoOtp) {
      item.textContent = state.demoOtp;
      item.closest(".demo-otp")?.classList.remove("hidden");
    }
  });
  startResendTimer(Number(state.resendAfter || 60));

  form.addEventListener("submit", async (event) => {
    event.preventDefault();
    setLoading(form, true);
    showMessage("", "");
    const data = new FormData(form);
    try {
      const result = await apiFetch("/api/auth/otp/verify", {
        method: "POST",
        body: {
          email: state.email,
          purpose: state.purpose || "login",
          otp: data.get("otp")
        }
      });
      if (result.resetToken) {
        saveAuthState({ resetToken: result.resetToken });
        window.location.href = result.redirectTo || "/reset-password.html";
        return;
      }
      showMessage("success", result.message || "OTP verified.");
      window.setTimeout(() => {
        window.location.href = result.redirectTo || "/dashboard.html";
      }, 700);
    } catch (error) {
      showMessage("error", error.message);
    } finally {
      setLoading(form, false);
    }
  });

  document.querySelector("[data-resend-otp]")?.addEventListener("click", async () => {
    try {
      const result = await apiFetch("/api/auth/otp/resend", {
        method: "POST",
        body: {
          email: state.email,
          purpose: state.purpose || "login",
          channel: state.channel || "email"
        }
      });
      if (result.demoOtp) {
        saveAuthState({ demoOtp: result.demoOtp });
        document.querySelectorAll("[data-demo-otp]").forEach((item) => {
          item.textContent = result.demoOtp;
          item.closest(".demo-otp")?.classList.remove("hidden");
        });
      }
      showMessage("success", result.message);
      startResendTimer(result.resendAfter || 60);
    } catch (error) {
      showMessage("error", error.message);
    }
  });
}

function initResetPassword() {
  const form = document.getElementById("auth-reset-form");
  if (!form) return;
  form.addEventListener("submit", async (event) => {
    event.preventDefault();
    const data = new FormData(form);
    if (data.get("password") !== data.get("confirmPassword")) {
      showMessage("error", "Passwords do not match.");
      return;
    }
    setLoading(form, true);
    try {
      const result = await apiFetch("/api/auth/reset-password", {
        method: "POST",
        body: {
          resetToken: authState().resetToken,
          password: data.get("password")
        }
      });
      showMessage("success", result.message);
      sessionStorage.removeItem(authStateKey);
      window.setTimeout(() => {
        window.location.href = result.redirectTo || "/login.html";
      }, 900);
    } catch (error) {
      showMessage("error", error.message);
    } finally {
      setLoading(form, false);
    }
  });
}

document.addEventListener("DOMContentLoaded", () => {
  initAuthBackground();
  initOtpInputs();
  initLogin();
  initSignup();
  initForgotPassword();
  initVerifyOtp();
  initResetPassword();
});
