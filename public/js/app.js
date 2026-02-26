// app.js — Auth Portal frontend logic

const API = "";

// ── Helper: show message ───────────────────
function showMsg(text, type = "error") {
  const el = document.getElementById("msg");
  if (!el) return;
  el.textContent = text;
  el.className = "message " + type;
}

function clearMsg() {
  const el = document.getElementById("msg");
  if (!el) return;
  el.className = "message";
  el.textContent = "";
}

// ── Auth Header Helper ─────────────────────
function authHeaders(extra = {}) {
  const token = localStorage.getItem("token");
  return {
    "Content-Type": "application/json",
    ...(token ? { Authorization: "Bearer " + token } : {}),
    ...extra,
  };
}

// ── Get redirect URL from query params ─────
function getRedirectUrl() {
  const params = new URLSearchParams(window.location.search);
  return params.get("redirect") || null;
}

// ── Login ──────────────────────────────────
async function login(username, password) {
  clearMsg();
  try {
    const res = await fetch(API + "/api/login", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ username, password }),
    });
    const data = await res.json();

    if (!res.ok) {
      showMsg(data.error || "登入失敗");
      return;
    }

    localStorage.setItem("token", data.token);
    localStorage.setItem("username", data.username);

    // Check for redirect URL (cross-app auth flow)
    const redirectUrl = getRedirectUrl();
    if (redirectUrl) {
      const separator = redirectUrl.includes("?") ? "&" : "?";
      window.location.href = redirectUrl + separator + "token=" + data.token;
    } else {
      window.location.href = "/dashboard.html";
    }
  } catch {
    showMsg("無法連接伺服器");
  }
}

// ── Register ───────────────────────────────
async function register(username, password, password2, securityQuestion, securityAnswer) {
  clearMsg();

  if (password !== password2) {
    showMsg("兩次密碼不一致");
    return;
  }

  if (!securityQuestion) {
    showMsg("請選擇一個安全問題");
    return;
  }

  if (!securityAnswer) {
    showMsg("請輸入安全問題的答案");
    return;
  }

  try {
    const res = await fetch(API + "/api/register", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ username, password, securityQuestion, securityAnswer }),
    });
    const data = await res.json();

    if (!res.ok) {
      showMsg(data.error || "註冊失敗");
      return;
    }

    // Preserve redirect param when going to login
    const redirectUrl = getRedirectUrl();
    const loginUrl = redirectUrl ? "/?redirect=" + encodeURIComponent(redirectUrl) : "/";
    showMsg("註冊成功！正在跳轉到登入頁…", "success");
    setTimeout(() => (window.location.href = loginUrl), 1500);
  } catch {
    showMsg("無法連接伺服器");
  }
}

// ── Forgot Password ────────────────────────
async function forgotPasswordVerify(username) {
  clearMsg();

  if (!username) {
    showMsg("請輸入用戶名");
    return;
  }

  try {
    const res = await fetch(API + "/api/forgot-password/verify", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ username }),
    });
    const data = await res.json();

    if (!res.ok) {
      showMsg(data.error || "驗證失敗");
      return;
    }

    // Show step 2
    const step1 = document.getElementById("step1Form");
    const step2 = document.getElementById("step2Form");
    const questionText = document.getElementById("securityQuestionText");

    if (step1) step1.style.display = "none";
    if (step2) step2.style.display = "block";
    if (questionText) questionText.textContent = data.securityQuestion;

    showMsg("請回答安全問題以重設密碼", "success");
  } catch {
    showMsg("無法連接伺服器");
  }
}

async function forgotPasswordReset(username, securityAnswer, newPassword, newPassword2) {
  clearMsg();

  if (!securityAnswer) {
    showMsg("請輸入安全問題的答案");
    return;
  }
  if (!newPassword || newPassword.length < 6) {
    showMsg("新密碼至少 6 個字元");
    return;
  }
  if (newPassword !== newPassword2) {
    showMsg("兩次密碼不一致");
    return;
  }

  try {
    const res = await fetch(API + "/api/forgot-password/reset", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ username, securityAnswer, newPassword }),
    });
    const data = await res.json();

    if (!res.ok) {
      showMsg(data.error || "重設失敗");
      return;
    }

    showMsg("密碼重設成功！正在跳轉到登入頁…", "success");
    setTimeout(() => (window.location.href = "/"), 2000);
  } catch {
    showMsg("無法連接伺服器");
  }
}

// ── Auth Check (for protected pages) ───────
async function checkAuth() {
  const token = localStorage.getItem("token");

  if (!token) {
    window.location.href = "/";
    return;
  }

  try {
    const res = await fetch(API + "/api/me", {
      headers: { Authorization: "Bearer " + token },
    });

    if (!res.ok) {
      localStorage.removeItem("token");
      localStorage.removeItem("username");
      window.location.href = "/";
      return;
    }

    const user = await res.json();

    // Update topbar badge
    const badgeEl = document.getElementById("userBadge");
    if (badgeEl) badgeEl.textContent = "👤 " + user.username;

    return user;
  } catch {
    localStorage.removeItem("token");
    localStorage.removeItem("username");
    window.location.href = "/";
  }
}

// ── Logout ─────────────────────────────────
function logout() {
  localStorage.removeItem("token");
  localStorage.removeItem("username");
  window.location.href = "/";
}

// ══════════════════════════════════════════════
//  SETTINGS FUNCTIONS
// ══════════════════════════════════════════════

async function loadSettings() {
  try {
    const res = await fetch(API + "/api/settings", {
      headers: authHeaders(),
    });

    if (!res.ok) return;
    const data = await res.json();

    const statusEl = document.getElementById("settingsStatus");
    const keyHint = document.getElementById("keyHint");

    if (data.api_key_set) {
      if (statusEl)
        statusEl.innerHTML =
          '<span class="status-ok">✅ API Key 已設定（' +
          escapeHtml(data.api_key_masked) +
          "）</span>";
      if (keyHint)
        keyHint.textContent =
          "目前已設定金鑰（" + data.api_key_masked + "），重新輸入可覆蓋";
    } else {
      if (statusEl)
        statusEl.innerHTML =
          '<span class="status-none">❌ 尚未設定 API Key</span>';
      if (keyHint) keyHint.textContent = "";
    }

    const baseUrlEl = document.getElementById("apiBaseUrl");
    const modelEl = document.getElementById("apiModel");
    const modeEl = document.getElementById("apiMode");

    if (baseUrlEl && data.api_base_url) baseUrlEl.value = data.api_base_url;
    if (modelEl && data.api_model) modelEl.value = data.api_model;
    if (modeEl && data.api_mode) modeEl.value = data.api_mode;

    if (typeof updateApiModeHints === "function") updateApiModeHints();
  } catch (err) {
    console.error("loadSettings error:", err);
  }
}

async function saveSettings(event) {
  if (event) event.preventDefault();

  const apiBaseUrl =
    document.getElementById("apiBaseUrl")?.value?.trim() || "";
  const apiKey = document.getElementById("apiKey")?.value?.trim() || "";
  const apiModel =
    document.getElementById("apiModel")?.value?.trim() ||
    "gemini-3-pro-image-preview";
  const apiMode = document.getElementById("apiMode")?.value || "chat";
  const msgEl = document.getElementById("settingsMsg");
  const btn = document.getElementById("saveBtn");
  const btnText = document.getElementById("saveBtnText");
  const btnSpinner = document.getElementById("saveBtnSpinner");

  if (!apiKey) {
    if (msgEl) {
      msgEl.textContent = "請輸入 API Key";
      msgEl.className = "settings-msg error";
    }
    return;
  }

  if (btn) btn.disabled = true;
  if (btnText) btnText.textContent = "儲存中…";
  if (btnSpinner) btnSpinner.style.display = "inline-block";

  try {
    const res = await fetch(API + "/api/settings/api-key", {
      method: "POST",
      headers: authHeaders(),
      body: JSON.stringify({
        api_base_url: apiBaseUrl,
        api_key: apiKey,
        api_model: apiModel,
        api_mode: apiMode,
      }),
    });

    const data = await res.json();

    if (res.ok) {
      if (msgEl) {
        msgEl.textContent = "✅ " + data.message;
        msgEl.className = "settings-msg success";
      }
      document.getElementById("apiKey").value = "";
      loadSettings();
    } else {
      if (msgEl) {
        msgEl.textContent = "❌ " + (data.error || "儲存失敗");
        msgEl.className = "settings-msg error";
      }
    }
  } catch (err) {
    if (msgEl) {
      msgEl.textContent = "❌ 無法連接伺服器";
      msgEl.className = "settings-msg error";
    }
  } finally {
    if (btn) btn.disabled = false;
    if (btnText) btnText.textContent = "💾 儲存設定";
    if (btnSpinner) btnSpinner.style.display = "none";
  }
}

async function testKey() {
  const testBtn = document.getElementById("testBtn");
  const resultEl = document.getElementById("testResult");

  if (testBtn) {
    testBtn.disabled = true;
    testBtn.textContent = "🧪 測試中…";
  }
  if (resultEl) {
    resultEl.style.display = "block";
    resultEl.textContent = "正在測試連線…";
    resultEl.className = "test-result testing";
  }

  try {
    const res = await fetch(API + "/api/settings/test-key", {
      method: "POST",
      headers: authHeaders(),
    });

    const data = await res.json();

    if (resultEl) {
      resultEl.textContent =
        data.message || (data.success ? "✅ 成功" : "❌ 失敗");
      resultEl.className =
        "test-result " + (data.success ? "success" : "error");
    }
  } catch (err) {
    if (resultEl) {
      resultEl.textContent = "❌ 無法連接伺服器";
      resultEl.className = "test-result error";
    }
  } finally {
    if (testBtn) {
      testBtn.disabled = false;
      testBtn.textContent = "🧪 測試連線";
    }
  }
}

async function deleteKey() {
  if (!confirm("確定要清除 API 設定嗎？")) return;

  const deleteBtn = document.getElementById("deleteBtn");
  const msgEl = document.getElementById("settingsMsg");

  if (deleteBtn) {
    deleteBtn.disabled = true;
    deleteBtn.textContent = "清除中…";
  }

  try {
    const res = await fetch(API + "/api/settings/api-key", {
      method: "DELETE",
      headers: authHeaders(),
    });

    const data = await res.json();

    if (res.ok) {
      if (msgEl) {
        msgEl.textContent = "✅ " + data.message;
        msgEl.className = "settings-msg success";
      }
      document.getElementById("apiBaseUrl").value = "";
      document.getElementById("apiKey").value = "";
      document.getElementById("apiModel").value = "gemini-3-pro-image-preview";
      loadSettings();
    } else {
      if (msgEl) {
        msgEl.textContent = "❌ " + (data.error || "清除失敗");
        msgEl.className = "settings-msg error";
      }
    }
  } catch (err) {
    if (msgEl) {
      msgEl.textContent = "❌ 無法連接伺服器";
      msgEl.className = "settings-msg error";
    }
  } finally {
    if (deleteBtn) {
      deleteBtn.disabled = false;
      deleteBtn.textContent = "🗑️ 清除設定";
    }
  }
}

function toggleKeyVisibility() {
  const input = document.getElementById("apiKey");
  const icon = document.getElementById("eyeIcon");
  if (!input) return;

  if (input.type === "password") {
    input.type = "text";
    if (icon) icon.textContent = "🙈";
  } else {
    input.type = "password";
    if (icon) icon.textContent = "👁️";
  }
}

function updateApiModeHints() {
  const modeEl = document.getElementById("apiMode");
  const modeHint = document.getElementById("modeHint");
  const baseUrlHint = document.getElementById("baseUrlHint");
  const modelHint = document.getElementById("modelHint");
  const baseUrlEl = document.getElementById("apiBaseUrl");
  const modelEl = document.getElementById("apiModel");

  if (!modeEl) return;
  const mode = modeEl.value;

  if (mode === "images") {
    if (modeHint) modeHint.textContent = "使用標準 /v1/images/generations 端點（OpenAI DALL·E 等）";
    if (baseUrlHint) baseUrlHint.textContent = "例如：https://api.openai.com/v1";
    if (modelHint) modelHint.textContent = "例如：dall-e-3、dall-e-2";
    if (baseUrlEl && !baseUrlEl.value) baseUrlEl.placeholder = "https://api.openai.com/v1";
    if (modelEl && (!modelEl.value || modelEl.value === "gemini-3-pro-image-preview")) modelEl.value = "dall-e-3";
  } else {
    if (modeHint) modeHint.textContent = "使用 chat/completions 端點，模型回傳包含圖片的回應";
    if (baseUrlHint) baseUrlHint.textContent = "留空則使用預設值 (Google Gemini API)";
    if (modelHint) modelHint.textContent = "圖片生成使用的模型名稱";
    if (baseUrlEl && !baseUrlEl.value) baseUrlEl.placeholder = "https://generativelanguage.googleapis.com/v1beta/openai";
    if (modelEl && (!modelEl.value || modelEl.value === "dall-e-3")) modelEl.value = "gemini-3-pro-image-preview";
  }
}

// ── Helper ─────────────────────────────────
function escapeHtml(text) {
  const div = document.createElement("div");
  div.textContent = text;
  return div.innerHTML;
}
