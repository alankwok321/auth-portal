const express = require("express");
const cors = require("cors");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const path = require("path");
const { db, initDB } = require("./db");

const app = express();
const JWT_SECRET = process.env.JWT_SECRET || "auth-portal-secret-change-me";
const PORT = process.env.PORT || 3000;

// ── Middleware ──────────────────────────────
app.use(cors({ origin: true, credentials: true }));
app.use(express.json());
app.use(express.static(path.join(__dirname, "public")));

// ── Auth Middleware ─────────────────────────
function authMiddleware(req, res, next) {
  const header = req.headers.authorization;
  if (!header || !header.startsWith("Bearer ")) {
    return res.status(401).json({ error: "未登入" });
  }
  try {
    const decoded = jwt.verify(header.split(" ")[1], JWT_SECRET);
    req.user = decoded;
    next();
  } catch {
    return res.status(401).json({ error: "登入已過期，請重新登入" });
  }
}

// ══════════════════════════════════════════════
//  AUTH ENDPOINTS
// ══════════════════════════════════════════════

// ── Register ───────────────────────────────
app.post("/api/register", async (req, res) => {
  try {
    const { username, password, securityQuestion, securityAnswer } = req.body;

    if (!username || !password) {
      return res.status(400).json({ error: "請填寫用戶名和密碼" });
    }
    if (username.length < 3) {
      return res.status(400).json({ error: "用戶名至少 3 個字元" });
    }
    if (password.length < 6) {
      return res.status(400).json({ error: "密碼至少 6 個字元" });
    }
    if (!securityQuestion || !securityAnswer) {
      return res.status(400).json({ error: "請選擇安全問題並輸入答案" });
    }

    // Check if user already exists
    const existing = await db.execute({
      sql: "SELECT id FROM users WHERE username = ?",
      args: [username],
    });
    if (existing.rows.length > 0) {
      return res.status(409).json({ error: "此用戶名已被使用" });
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    const hashedAnswer = await bcrypt.hash(securityAnswer.toLowerCase(), 10);

    await db.execute({
      sql: "INSERT INTO users (username, password, security_question, security_answer) VALUES (?, ?, ?, ?)",
      args: [username, hashedPassword, securityQuestion, hashedAnswer],
    });

    res.json({ message: "註冊成功" });
  } catch (err) {
    console.error("Register error:", err);
    res.status(500).json({ error: "伺服器錯誤" });
  }
});

// ── Login ──────────────────────────────────
app.post("/api/login", async (req, res) => {
  try {
    const { username, password } = req.body;

    if (!username || !password) {
      return res.status(400).json({ error: "請填寫用戶名和密碼" });
    }

    const result = await db.execute({
      sql: "SELECT * FROM users WHERE username = ?",
      args: [username],
    });

    if (result.rows.length === 0) {
      return res.status(401).json({ error: "用戶名或密碼錯誤" });
    }

    const user = result.rows[0];
    const valid = await bcrypt.compare(password, user.password);
    if (!valid) {
      return res.status(401).json({ error: "用戶名或密碼錯誤" });
    }

    const token = jwt.sign(
      { id: user.id, username: user.username },
      JWT_SECRET,
      { expiresIn: "7d" }
    );

    res.json({ token, username: user.username });
  } catch (err) {
    console.error("Login error:", err);
    res.status(500).json({ error: "伺服器錯誤" });
  }
});

// ── Forgot Password: Verify ────────────────
app.post("/api/forgot-password/verify", async (req, res) => {
  try {
    const { username } = req.body;

    if (!username) {
      return res.status(400).json({ error: "請輸入用戶名" });
    }

    const result = await db.execute({
      sql: "SELECT security_question FROM users WHERE username = ?",
      args: [username],
    });

    if (result.rows.length === 0) {
      return res.status(404).json({ error: "找不到此用戶" });
    }

    res.json({ securityQuestion: result.rows[0].security_question });
  } catch (err) {
    console.error("Forgot password verify error:", err);
    res.status(500).json({ error: "伺服器錯誤" });
  }
});

// ── Forgot Password: Reset ─────────────────
app.post("/api/forgot-password/reset", async (req, res) => {
  try {
    const { username, securityAnswer, newPassword } = req.body;

    if (!username || !securityAnswer || !newPassword) {
      return res.status(400).json({ error: "請填寫所有欄位" });
    }
    if (newPassword.length < 6) {
      return res.status(400).json({ error: "新密碼至少 6 個字元" });
    }

    const result = await db.execute({
      sql: "SELECT * FROM users WHERE username = ?",
      args: [username],
    });

    if (result.rows.length === 0) {
      return res.status(404).json({ error: "找不到此用戶" });
    }

    const user = result.rows[0];
    const answerMatch = await bcrypt.compare(
      securityAnswer.toLowerCase(),
      user.security_answer
    );

    if (!answerMatch) {
      return res.status(401).json({ error: "安全問題答案錯誤" });
    }

    const hashedPassword = await bcrypt.hash(newPassword, 10);
    await db.execute({
      sql: "UPDATE users SET password = ? WHERE id = ?",
      args: [hashedPassword, user.id],
    });

    res.json({ message: "密碼重設成功" });
  } catch (err) {
    console.error("Forgot password reset error:", err);
    res.status(500).json({ error: "伺服器錯誤" });
  }
});

// ── Get Current User ───────────────────────
app.get("/api/me", authMiddleware, async (req, res) => {
  try {
    const result = await db.execute({
      sql: "SELECT id, username, created_at FROM users WHERE id = ?",
      args: [req.user.id],
    });

    if (result.rows.length === 0) {
      return res.status(404).json({ error: "用戶不存在" });
    }

    const user = result.rows[0];
    res.json({
      id: user.id,
      username: user.username,
      created_at: user.created_at,
    });
  } catch (err) {
    console.error("Get me error:", err);
    res.status(500).json({ error: "伺服器錯誤" });
  }
});

// ── Verify Token (for other apps) ──────────
app.get("/api/verify-token", authMiddleware, async (req, res) => {
  res.json({ valid: true, user: { id: req.user.id, username: req.user.username } });
});

// ══════════════════════════════════════════════
//  SETTINGS ENDPOINTS
// ══════════════════════════════════════════════

// ── Get Settings ───────────────────────────
app.get("/api/settings", authMiddleware, async (req, res) => {
  try {
    const result = await db.execute({
      sql: "SELECT api_base_url, api_key, api_model, api_mode FROM users WHERE id = ?",
      args: [req.user.id],
    });

    if (result.rows.length === 0) {
      return res.status(404).json({ error: "用戶不存在" });
    }

    const user = result.rows[0];
    const hasKey = !!user.api_key;

    res.json({
      api_key_set: hasKey,
      api_key_masked: hasKey
        ? user.api_key.substring(0, 4) + "..." + user.api_key.substring(user.api_key.length - 4)
        : null,
      api_base_url: user.api_base_url || "",
      api_model: user.api_model || "",
      api_mode: user.api_mode || "chat",
    });
  } catch (err) {
    console.error("Get settings error:", err);
    res.status(500).json({ error: "伺服器錯誤" });
  }
});

// ── Save API Key Settings ──────────────────
app.post("/api/settings/api-key", authMiddleware, async (req, res) => {
  try {
    const { api_base_url, api_key, api_model, api_mode } = req.body;

    if (!api_key) {
      return res.status(400).json({ error: "請輸入 API Key" });
    }

    await db.execute({
      sql: "UPDATE users SET api_base_url = ?, api_key = ?, api_model = ?, api_mode = ? WHERE id = ?",
      args: [
        api_base_url || null,
        api_key,
        api_model || null,
        api_mode || "chat",
        req.user.id,
      ],
    });

    res.json({ message: "API 設定已儲存" });
  } catch (err) {
    console.error("Save settings error:", err);
    res.status(500).json({ error: "伺服器錯誤" });
  }
});

// ── Delete API Key Settings ────────────────
app.delete("/api/settings/api-key", authMiddleware, async (req, res) => {
  try {
    await db.execute({
      sql: "UPDATE users SET api_base_url = NULL, api_key = NULL, api_model = NULL, api_mode = NULL WHERE id = ?",
      args: [req.user.id],
    });

    res.json({ message: "API 設定已清除" });
  } catch (err) {
    console.error("Delete settings error:", err);
    res.status(500).json({ error: "伺服器錯誤" });
  }
});

// ── Test API Key ───────────────────────────
app.post("/api/settings/test-key", authMiddleware, async (req, res) => {
  try {
    const result = await db.execute({
      sql: "SELECT api_base_url, api_key, api_model, api_mode FROM users WHERE id = ?",
      args: [req.user.id],
    });

    if (result.rows.length === 0) {
      return res.status(404).json({ error: "用戶不存在" });
    }

    const user = result.rows[0];

    if (!user.api_key) {
      return res.json({ success: false, message: "❌ 尚未設定 API Key" });
    }

    const mode = user.api_mode || "chat";
    const baseUrl =
      user.api_base_url ||
      (mode === "images"
        ? "https://api.openai.com/v1"
        : "https://generativelanguage.googleapis.com/v1beta/openai");
    const model = user.api_model || (mode === "images" ? "dall-e-3" : "gemini-3-pro-image-preview");

    // Test with a simple models list request
    const testUrl = baseUrl.replace(/\/+$/, "") + "/models";
    const testRes = await fetch(testUrl, {
      headers: { Authorization: "Bearer " + user.api_key },
      signal: AbortSignal.timeout(10000),
    });

    if (testRes.ok) {
      res.json({
        success: true,
        message: `✅ 連線成功！模式: ${mode === "images" ? "Images API" : "Chat Completions"}, 模型: ${model}`,
      });
    } else {
      const errText = await testRes.text().catch(() => "");
      res.json({
        success: false,
        message: `❌ API 回應 ${testRes.status}: ${errText.substring(0, 200)}`,
      });
    }
  } catch (err) {
    res.json({
      success: false,
      message: `❌ 連線失敗: ${err.message || "未知錯誤"}`,
    });
  }
});

// ══════════════════════════════════════════════
//  SERVE STATIC HTML PAGES
// ══════════════════════════════════════════════

const htmlPages = [
  "register.html",
  "forgot-password.html",
  "settings.html",
  "dashboard.html",
];

htmlPages.forEach((page) => {
  app.get("/" + page, (req, res) => {
    res.sendFile(path.join(__dirname, "public", page));
  });
});

// Catch-all: serve index.html (login page)
app.get("*", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "index.html"));
});

// ── Start ──────────────────────────────────
initDB()
  .then(() => {
    if (process.env.VERCEL) {
      module.exports = app;
    } else {
      app.listen(PORT, () => {
        console.log(`🚀 Auth Portal running on http://localhost:${PORT}`);
      });
    }
  })
  .catch((err) => {
    console.error("Failed to init DB:", err);
    process.exit(1);
  });

// Export for Vercel
module.exports = app;
