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

const sha256 = (s) => crypto.createHash("sha256").update(s).digest("hex");

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

// Tạo key: POST /admin/create  {"days":30,"note":"khach A"}
app.post("/admin/create", admin, async (req, res) => {
  const { days, note } = req.body || {};
  const key = "LIC-" + crypto.randomBytes(16).toString("hex").toUpperCase();
  const expires = days ? new Date(Date.now() + days * 86400000) : null;
  await pool.query(
    "INSERT INTO license_keys (key_hash, prefix, note, expires_at) VALUES ($1,$2,$3,$4)",
    [sha256(key), key.slice(0, 8), note || null, expires]
  );
  res.json({ ok: true, key, expires_at: expires }); // key chỉ hiện 1 lần này
});

// Thu hồi: POST /admin/revoke  {"prefix":"LIC-AB12"}
app.post("/admin/revoke", admin, async (req, res) => {
  const r = await pool.query(
    "UPDATE license_keys SET status='revoked' WHERE prefix=$1",
    [req.body.prefix]
  );
  res.json({ ok: true, updated: r.rowCount });
});

// App gọi: POST /activate  {"key":"LIC-...","device_id":"..."}
app.post("/activate", async (req, res) => {
  const { key, device_id } = req.body || {};
  if (!key || !device_id)
    return res.status(400).json({ ok: false, error: "missing_fields" });

  const r = await pool.query("SELECT * FROM license_keys WHERE key_hash=$1", [
    sha256(key),
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
});

app.get("/", (_, res) => res.send("ok"));

init().then(() =>
  app.listen(process.env.PORT || 3000, () => console.log("running"))
);
