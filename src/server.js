import "dotenv/config";
import express from "express";
import pg from "pg";

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

app.use(express.json({ limit: "1mb" }));
app.use((_req, res, next) => { res.setHeader("Cache-Control", "no-store"); next(); });
app.use(express.static("public"));

const pool = process.env.DATABASE_URL
  ? new Pool({
      connectionString: process.env.DATABASE_URL,
      ssl: { rejectUnauthorized: false }
    })
  : null;

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

app.listen(port, () => {
  console.log(`Tiffin Delivery System running on port ${port}`);
});
