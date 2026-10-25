"use strict";

async function api(path, method = "GET", payload = null) {
  const options = { method, credentials: "same-origin", headers: {} };
  if (payload !== null) {
    options.headers["Content-Type"] = "application/json";
    options.body = JSON.stringify(payload);
  }
  const response = await fetch(path, options);
  const data = await response.json().catch(() => ({}));
  if (!response.ok) {
    const error = new Error(typeof data.detail === "string" ? data.detail : "Request failed");
    error.status = response.status;
    throw error;
  }
  return { status: response.status, data };
}

function showResult(elementId, message, success = false) {
  const element = document.getElementById(elementId);
  if (!element) return;
  element.textContent = message;
  element.classList.toggle("success", success);
}

function credentialsFrom(form) {
  return { username: form.elements.username.value, password: form.elements.password.value };
}

function setupHome() {
  const registerForm = document.getElementById("register-form");
  registerForm.addEventListener("submit", async (event) => {
    event.preventDefault();
    if (!registerForm.reportValidity()) return;
    try {
      const result = await api("/api/register", "POST", credentialsFrom(registerForm));
      showResult("register-message", `${result.status}: ${result.data.message}`, true);
      registerForm.reset();
    } catch (error) {
      showResult("register-message", `${error.status || "Error"}: ${error.message}`);
    }
  });

  const loginForm = document.getElementById("login-form");
  loginForm.addEventListener("submit", async (event) => {
    event.preventDefault();
    if (!loginForm.reportValidity()) return;
    try {
      await api("/api/login", "POST", credentialsFrom(loginForm));
      window.location.assign("/dashboard");
    } catch (error) {
      showResult("login-message", `${error.status || "Error"}: ${error.message}`);
    }
  });

  document.getElementById("check-guest").addEventListener("click", async () => {
    try {
      const result = await api("/api/user");
      showResult("guest-result", `GET /api/user → ${result.status} OK`, true);
    } catch (error) {
      showResult("guest-result", `GET /api/user → ${error.status || "Error"}: ${error.message}`);
    }
  });
}

async function setupDashboard() {
  try {
    const result = await api("/api/user");
    document.getElementById("welcome").textContent = `Welcome, ${result.data.username}`;
    document.getElementById("user-detail").textContent = `Role: ${result.data.role} · GET /api/user: ${result.status} OK`;
  } catch (error) {
    showResult("dashboard-result", `${error.status || "Error"}: ${error.message}`);
  }
  document.getElementById("check-admin").addEventListener("click", async () => {
    try {
      const result = await api("/api/admin");
      showResult("dashboard-result", `GET /api/admin → ${result.status} OK`, true);
    } catch (error) {
      showResult("dashboard-result", `GET /api/admin → ${error.status || "Error"}: ${error.message}`);
    }
  });
}

async function setupAdmin() {
  try {
    const result = await api("/api/admin");
    document.getElementById("admin-welcome").textContent = `Welcome, ${result.data.username}`;
    document.getElementById("user-count").textContent = result.data.user_count;
    showResult("admin-result", `GET /api/admin → ${result.status} OK`, true);
  } catch (error) {
    showResult("admin-result", `${error.status || "Error"}: ${error.message}`);
  }
}

function setupLogout() {
  const button = document.getElementById("logout");
  if (!button) return;
  button.addEventListener("click", async () => {
    try {
      await api("/api/logout", "POST");
      window.location.assign("/");
    } catch (error) {
      showResult(document.body.dataset.page === "admin" ? "admin-result" : "dashboard-result", error.message);
    }
  });
}

const page = document.body.dataset.page;
if (page === "home") setupHome();
if (page === "dashboard") setupDashboard();
if (page === "admin") setupAdmin();
setupLogout();

