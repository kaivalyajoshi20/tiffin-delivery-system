import test from "node:test";
import assert from "node:assert/strict";

const base = (process.env.SMOKE_BASE_URL || "https://tiffin-delivery-demo.onrender.com").replace(/\/$/, "");

test("production health endpoint responds with database connected", async () => {
  const response = await fetch(base + "/api/health", { signal: AbortSignal.timeout(15000) });
  assert.equal(response.status, 200, "health endpoint should return HTTP 200");
  const body = await response.json();
  assert.equal(body.status, "ok");
  assert.equal(body.database, "connected");
});

test("security headers are present", async () => {
  const response = await fetch(base + "/api/health", { signal: AbortSignal.timeout(15000) });
  assert.equal(response.headers.get("x-content-type-options"), "nosniff");
  assert.equal(response.headers.get("x-frame-options"), "DENY");
  assert.ok(response.headers.get("strict-transport-security"), "HSTS should be enabled in production");
});

test("protected endpoint rejects unauthenticated access", async () => {
  const response = await fetch(base + "/api/me", { redirect: "manual", signal: AbortSignal.timeout(15000) });
  assert.equal(response.status, 401);
});

test("unsafe API request without CSRF token is rejected", async () => {
  const response = await fetch(base + "/api/logout", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: "{}",
    redirect: "manual",
    signal: AbortSignal.timeout(15000)
  });
  assert.equal(response.status, 403);
});
