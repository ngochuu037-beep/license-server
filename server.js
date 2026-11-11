const express = require("express");
const crypto = require("crypto");
const { Pool } = require("pg");

const app = express();
app.use(express.json());

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false },
});

const ADMIN_KEY = process.env.ADMIN_KEY; // đặt trong Variables của Railway
const BOT_TOKEN = process.env.BOT_TOKEN; // token từ @BotFather
const ADMIN_CHAT_ID = String(process.env.ADMIN_CHAT_ID || ""); // ID Telegram của bạn

const sha256 = (s) => crypto.createHash("sha256").update(s).digest("hex");
const genKey = () => "LIC-" + crypto.randomBytes(16).toString("hex").toUpperCase();

// Bọc route async để lỗi không làm crash server
const wrap = (fn) => (req, res) =>
  fn(req, res).catch((e) => {
    console.error(e);
    res.status(500).json({ ok: false, error: "server_error" });
  });

async function init() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS license_keys (
      id SERIAL PRIMARY KEY,
      key_hash TEXT UNIQUE NOT NULL,
      prefix TEXT NOT NULL,
      note TEXT,
      device_id TEXT,
      status TEXT NOT NULL DEFAULT 'active',
      expires_at TIMESTAMPTZ,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    )`);
}

function admin(req, res, next) {
  if (!ADMIN_KEY || req.get("x-admin-key") !== ADMIN_KEY)
    return res.status(401).json({ ok: false, error: "unauthorized" });
  next();
}

// ---------- Tạo key (dùng chung cho API và bot) ----------
async function createKey(days, note) {
  const key = genKey();
  const expires = days ? new Date(Date.now() + days * 86400000) : null;
  await pool.query(
    "INSERT INTO license_keys (key_hash, prefix, note, expires_at) VALUES ($1,$2,$3,$4)",
    [sha256(key), key.slice(0, 8), note || null, expires]
  );
  return { key, expires };
}

// ---------- API cho admin ----------
// POST /admin/create  {"days":30,"note":"khach A"}
app.post(
  "/admin/create",
  admin,
  wrap(async (req, res) => {
    const { days, note } = req.body || {};
    const { key, expires } = await createKey(days, note);
    res.json({ ok: true, key, expires_at: expires }); // key chỉ hiện 1 lần
  })
);

// POST /admin/revoke  {"prefix":"LIC-AB12"}
app.post(
  "/admin/revoke",
  admin,
  wrap(async (req, res) => {
    const r = await pool.query(
      "UPDATE license_keys SET status='revoked' WHERE prefix=$1",
      [String((req.body || {}).prefix || "").slice(0, 8)]
    );
    res.json({ ok: true, updated: r.rowCount });
  })
);

// ---------- API cho app ----------
// POST /activate  {"key":"LIC-...","device_id":"..."}
app.post(
  "/activate",
  wrap(async (req, res) => {
    const { key, device_id } = req.body || {};
    if (!key || !device_id)
      return res.status(400).json({ ok: false, error: "missing_fields" });

    const r = await pool.query("SELECT * FROM license_keys WHERE key_hash=$1", [
      sha256(String(key)),
    ]);
    const row = r.rows[0];
    if (!row) return res.json({ ok: false, error: "invalid_key" });
    if (row.status !== "active") return res.json({ ok: false, error: "revoked" });
    if (row.expires_at && new Date(row.expires_at) < new Date())
      return res.json({ ok: false, error: "expired" });

    if (!row.device_id) {
      // lần đầu: gắn key vào thiết bị này
      await pool.query("UPDATE license_keys SET device_id=$1 WHERE id=$2", [
        device_id,
        row.id,
      ]);
    } else if (row.device_id !== device_id) {
      return res.json({ ok: false, error: "used_on_other_device" });
    }
    res.json({ ok: true, expires_at: row.expires_at });
  })
);

app.get("/", (_, res) => res.send("ok"));

// ---------- Bot Telegram ----------
async function tg(method, body) {
  const r = await fetch(`https://api.telegram.org/bot${BOT_TOKEN}/${method}`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
  return r.json();
}

async function handle(msg) {
  const chat = String(msg.chat.id);
  if (chat !== ADMIN_CHAT_ID) return; // chỉ admin được dùng
  const [cmd, ...args] = (msg.text || "").trim().split(/\s+/);
  const reply = (text) => tg("sendMessage", { chat_id: chat, text });

  if (cmd === "/create") {
    const days = parseInt(args[0]) || null;
    const note = args.slice(1).join(" ") || null;
    const { key, expires } = await createKey(days, note);
    await reply(
      `Key: ${key}\nHạn: ${expires ? expires.toISOString().slice(0, 10) : "vĩnh viễn"}`
    );
  } else if (cmd === "/revoke" && args[0]) {
    const r = await pool.query(
      "UPDATE license_keys SET status='revoked' WHERE prefix=$1",
      [args[0].slice(0, 8)]
    );
    await reply(`Đã thu hồi: ${r.rowCount}`);
  } else if (cmd === "/list") {
    const r = await pool.query(
      "SELECT prefix, note, status, expires_at, device_id FROM license_keys ORDER BY id DESC LIMIT 10"
    );
    await reply(
      r.rows
        .map(
          (x) =>
            `${x.prefix} | ${x.status} | ${x.note || "-"} | ${
              x.device_id ? "đã dùng" : "chưa dùng"
            }`
        )
        .join("\n") || "Chưa có key"
    );
  } else {
    await reply("/create <số ngày> <ghi chú>\n/revoke <LIC-XXXX>\n/list");
  }
}

async function poll() {
  let offset = 0;
  while (true) {
    try {
      const r = await tg("getUpdates", { offset, timeout: 30 });
      if (!r.ok) throw new Error(JSON.stringify(r));
      for (const u of r.result) {
        offset = u.update_id + 1;
        if (u.message) await handle(u.message).catch(console.error);
      }
    } catch (e) {
      console.error(e);
      await new Promise((s) => setTimeout(s, 5000));
    }
  }
}

init().then(() => {
  app.listen(process.env.PORT || 3000, () => console.log("running"));
  if (BOT_TOKEN && ADMIN_CHAT_ID) poll();
});
// v2

