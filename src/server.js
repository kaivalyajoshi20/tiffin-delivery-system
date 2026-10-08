import "dotenv/config";
import express from "express";
import pg from "pg";
import crypto from "node:crypto";
import bcrypt from "bcryptjs";

const { Pool } = pg;
const app = express();
const port = Number(process.env.PORT || 3000);

app.disable("x-powered-by");
app.set("trust proxy", 1);
app.use((_req, res, next) => {
  res.setHeader("X-Content-Type-Options", "nosniff");
  res.setHeader("X-Frame-Options", "DENY");
  res.setHeader("Referrer-Policy", "strict-origin-when-cross-origin");
  res.setHeader("Permissions-Policy", "camera=(self), geolocation=(self), microphone=()");
  next();
});

const ALLOWED_ORIGINS = new Set([
  "https://instant-wjihasssodpr-angadphuket345-140e.wix-site-host.com",
  "http://localhost:3000",
  "http://localhost:5173"
]);

app.use((req, res, next) => {
  const origin = req.headers.origin;
  if (origin && ALLOWED_ORIGINS.has(origin)) {
    res.setHeader("Access-Control-Allow-Origin", origin);
    res.setHeader("Vary", "Origin");
    res.setHeader("Access-Control-Allow-Headers", "Content-Type, Authorization");
    res.setHeader("Access-Control-Allow-Methods", "GET,POST,OPTIONS");
  }
  if (req.method === "OPTIONS") return res.sendStatus(204);
  next();
});

app.use(express.json({ limit: "1mb" }));
app.use((_req, res, next) => { res.setHeader("Cache-Control", "no-store"); next(); });
app.use(express.static("public"));

const pool = process.env.DATABASE_URL
  ? new Pool({
      connectionString: process.env.DATABASE_URL,
      ssl: { rejectUnauthorized: false }
    })
  : null;

const SESSION_SECRET = process.env.SESSION_SECRET || "tiffinflow-demo-session-secret-change-before-production";

function createSessionToken(user) {
  const payload = Buffer.from(JSON.stringify({
    id: user.id,
    username: user.username,
    role: user.role,
    name: user.name,
    exp: Date.now() + 12 * 60 * 60 * 1000
  })).toString("base64url");
  const signature = crypto.createHmac("sha256", SESSION_SECRET).update(payload).digest("base64url");
  return payload + "." + signature;
}

function readSessionToken(token) {
  if (!token) return null;
  const parts = token.split(".");
  if (parts.length !== 2) return null;
  const [payload, signature] = parts;
  const expected = crypto.createHmac("sha256", SESSION_SECRET).update(payload).digest("base64url");
  if (signature.length !== expected.length || !crypto.timingSafeEqual(Buffer.from(signature), Buffer.from(expected))) return null;
  try {
    const session = JSON.parse(Buffer.from(payload, "base64url").toString("utf8"));
    if (!session.exp || session.exp < Date.now()) return null;
    return { id: session.id, username: session.username, role: session.role, name: session.name };
  } catch {
    return null;
  }
}

async function seedDemoUsers() {
  if (!pool || process.env.DEMO_SEED !== "true") return;
  const hash = await bcrypt.hash("demo123", 10);
  await pool.query(
    "UPDATE users SET password_hash = $1, updated_at = NOW() WHERE username IN ('admin','driver')",
    [hash]
  );
}


function requireAuth(req, res, next) {
  const token = req.headers.authorization?.replace(/^Bearer\s+/i, "");
  const session = readSessionToken(token);
  if (!session) return res.status(401).json({ error: "Unauthorized", message: "Please sign in again." });
  req.user = session;
  next();
}

app.post("/api/login", async (req, res, next) => {
  try {
    if (!pool) return res.status(503).json({ error: "Database unavailable", message: "Demo database is not configured." });
    const username = String(req.body?.username || "").trim().toLowerCase();
    const password = String(req.body?.password || "");
    if (!username || !password) return res.status(400).json({ error: "Invalid request", message: "Username and password are required." });
    const result = await pool.query(
      "SELECT id, username, password_hash, role, name FROM users WHERE username = $1 AND active = true LIMIT 1",
      [username]
    );
    const user = result.rows[0];
    if (!user || !(await bcrypt.compare(password, user.password_hash))) {
      return res.status(401).json({ error: "Invalid credentials", message: "Staff ID or password is incorrect." });
    }
    const safeUser = { id: user.id, username: user.username, role: user.role, name: user.name };
    const token = createSessionToken(safeUser);
    res.json({ token, user: safeUser });
  } catch (err) { next(err); }
});

app.post("/api/profile/password", requireAuth, async (req, res, next) => {
  try {
    const currentPassword = String(req.body?.currentPassword || "");
    const newPassword = String(req.body?.newPassword || "");
    if (!currentPassword || !newPassword) {
      return res.status(400).json({ error: "Invalid request", message: "Current and new password are required." });
    }
    if (newPassword.length < 8) {
      return res.status(400).json({ error: "Invalid password", message: "New password must be at least 8 characters." });
    }

    const result = await pool.query(
      "SELECT password_hash FROM users WHERE id = $1 AND active = true LIMIT 1",
      [req.user.id]
    );
    const user = result.rows[0];
    if (!user || !(await bcrypt.compare(currentPassword, user.password_hash))) {
      return res.status(401).json({ error: "Invalid credentials", message: "Current password is incorrect." });
    }

    const passwordHash = await bcrypt.hash(newPassword, 12);
    await pool.query(
      "UPDATE users SET password_hash = $1, updated_at = NOW() WHERE id = $2",
      [passwordHash, req.user.id]
    );
    res.json({ ok: true, message: "Password updated." });
  } catch (err) { next(err); }
});

app.post("/api/logout", requireAuth, (_req, res) => {
  res.json({ ok: true });
});

app.get("/api/deliveries", requireAuth, async (req, res, next) => {
  try {
    const params = [];
    let where = "WHERE d.delivery_date = CURRENT_DATE";
    if (req.user.role === "driver") { params.push(req.user.id); where += " AND d.driver_id = $1"; }
    const result = await pool.query(
      `SELECT d.id, d.delivery_code AS code, c.name AS customer, c.area, u.name AS driver,
              d.status, COALESCE(TO_CHAR(d.planned_time,'HH12:MI AM'), '') AS time,
              d.empty_photo_data IS NOT NULL AS has_empty_photo,
              d.delivery_photo_data IS NOT NULL AS has_delivery_photo,
              d.whatsapp_status
         FROM deliveries d
         JOIN customers c ON c.id=d.customer_id
         LEFT JOIN users u ON u.id=d.driver_id
         ${where}
         ORDER BY d.planned_time NULLS LAST, c.name`, params);
    res.json({ deliveries: result.rows });
  } catch (err) { next(err); }
});

app.post("/api/deliveries/:code/empty-proof", requireAuth, async (req, res, next) => {
  try {
    if (req.user.role !== "driver") return res.status(403).json({ error: "Forbidden", message: "Only delivery staff can collect empty tiffins." });
    const { photo, latitude, longitude } = req.body || {};
    if (!photo) return res.status(400).json({ error: "Photo required", message: "Take the empty-tiffin photo first." });
    const result = await pool.query(
      `UPDATE deliveries SET status='Empty Tiffin Collected', empty_photo_data=$1, empty_photo_at=NOW(), empty_latitude=$2, empty_longitude=$3, updated_at=NOW()
       WHERE delivery_code=$4 AND driver_id=$5 AND status IN ('Pending','Planned','Empty Tiffin Collected')
       RETURNING delivery_code AS code, status`, [photo, latitude ?? null, longitude ?? null, req.params.code, req.user.id]
    );
    if (!result.rows[0]) return res.status(404).json({ error: "Delivery not found", message: "This delivery is not assigned to you." });
    res.json({ delivery: result.rows[0] });
  } catch (err) { next(err); }
});

app.post("/api/deliveries/:code/complete", requireAuth, async (req, res, next) => {
  try {
    if (req.user.role !== "driver") return res.status(403).json({ error: "Forbidden", message: "Only delivery staff can complete deliveries." });
    const { photo, latitude, longitude } = req.body || {};
    if (!photo) return res.status(400).json({ error: "Photo required", message: "Take the delivery photo first." });
    const result = await pool.query(
      `UPDATE deliveries SET status='Delivered', delivery_photo_data=$1, delivery_photo_at=NOW(), delivered_at=NOW(), delivery_latitude=$2, delivery_longitude=$3, whatsapp_status='Sent (demo)', updated_at=NOW()
       WHERE delivery_code=$4 AND driver_id=$5 AND empty_photo_data IS NOT NULL AND status IN ('Empty Tiffin Collected','Pending')
       RETURNING delivery_code AS code, status, delivered_at`, [photo, latitude ?? null, longitude ?? null, req.params.code, req.user.id]
    );
    if (!result.rows[0]) return res.status(409).json({ error: "Workflow incomplete", message: "Collect the empty tiffin photo before completing delivery." });
    res.json({ delivery: result.rows[0], whatsapp: "Sent (demo)" });
  } catch (err) { next(err); }
});

app.get("/api/deliveries/:code/proof", requireAuth, async (req, res, next) => {
  try {
    const result = await pool.query(
      `SELECT d.delivery_code AS code, c.name AS customer, u.name AS driver, d.status,
              d.empty_photo_data, d.empty_photo_at, d.empty_latitude, d.empty_longitude,
              d.delivery_photo_data, d.delivery_photo_at, d.delivery_latitude, d.delivery_longitude,
              d.delivered_at, d.whatsapp_status
         FROM deliveries d JOIN customers c ON c.id=d.customer_id LEFT JOIN users u ON u.id=d.driver_id
        WHERE d.delivery_code=$1 AND ($2='admin' OR d.driver_id=$3)`, [req.params.code, req.user.role, req.user.id]);
    if (!result.rows[0]) return res.status(404).json({ error: "Not found", message: "Delivery proof not found." });
    res.json({ proof: result.rows[0] });
  } catch (err) { next(err); }
});

app.get("/api/health", async (_req, res) => {
  const health = {
    status: "ok",
    service: "tiffin-delivery-system",
    database: "not_configured"
  };

  if (pool) {
    try {
      await pool.query("SELECT 1");
      health.database = "connected";
    } catch {
      health.status = "degraded";
      health.database = "error";
    }
  }

  res.setHeader("Cache-Control", "no-store");
  res.status(health.status === "ok" ? 200 : 503).json(health);
});

app.use((_req, res) => {
  res.status(404).json({
    error: "Not Found",
    message: "The requested resource was not found."
  });
});

app.use((err, _req, res, _next) => {
  console.error(err);
  res.status(500).json({
    error: "Internal Server Error",
    message: "Something went wrong on the server."
  });
});

async function start() {
  try {
    await seedDemoUsers();
    app.listen(port, () => {
      console.log(`Tiffin Delivery System running on port ${port}`);
    });
  } catch (err) {
    console.error("Startup failed:", err);
    process.exit(1);
  }
}

start();

/* app.listen(port, () => {
  console.log(`Tiffin Delivery System running on port ${port}`);
}); */
