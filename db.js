const { createClient } = require("@libsql/client");

const db = createClient({
  url: process.env.TURSO_DATABASE_URL || "file:local.db",
  authToken: process.env.TURSO_AUTH_TOKEN || undefined,
});

async function initDB() {
  await db.execute(`
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      username TEXT UNIQUE NOT NULL,
      password TEXT NOT NULL,
      security_question TEXT,
      security_answer TEXT,
      api_base_url TEXT,
      api_key TEXT,
      api_model TEXT,
      api_mode TEXT,
      created_at TEXT DEFAULT (datetime('now'))
    )
  `);
  console.log("✅ Database initialized");
}

module.exports = { db, initDB };
