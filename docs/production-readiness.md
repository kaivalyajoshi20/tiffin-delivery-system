# Production readiness runbook

This application handles staff accounts, customer contact details, delivery addresses, GPS coordinates, and proof photos. Do not treat a successful build or deploy as proof that it is safe for real customer data.

## Release blockers

- [ ] Confirm which PostgreSQL instance is used by the service and that the production `DATABASE_URL` points to that exact database.
- [ ] Take and verify a database backup before schema work. Confirm a restore procedure; a backup that has never been tested is not a recovery plan.
- [ ] Check schema compatibility before deploying. The app currently performs schema changes from `migrate()` during startup.
- [ ] Investigate duplicate delivery records before creating/enforcing the unique key on `(customer_id, delivery_date, meal_type)`. Never delete or merge production rows automatically without an explicit, reviewed data-repair plan.
- [ ] Confirm the recurring-delivery/customer foreign-key types match in the existing database. Do not drop legacy tables or columns as a quick fix.
- [ ] Set `NODE_ENV=production`, `DATABASE_URL`, and a unique, high-entropy `SESSION_SECRET` of at least 32 characters in Render. Never commit secrets or paste them into issues/chat.
- [ ] Confirm PostgreSQL TLS works with certificate verification enabled; do not disable certificate verification to work around connection errors.
- [ ] Configure Render's health-check path to `/api/health` after verifying the endpoint returns HTTP 200 with `{"status":"ok","database":"connected"}`.
- [ ] Run the security smoke tests against the intended staging/live environment deliberately: `npm run test:smoke`. The default target is the current Render demo URL; use `SMOKE_BASE_URL` to select a different target. These tests make HTTP requests and should not be run against an unintended environment.
- [ ] Test admin and driver login, role permissions, CSRF rejection, logout, customer creation, delivery lifecycle, photo/GPS proof, reports, and password recovery with test accounts.
- [ ] Confirm the admin recovery email and driver phone numbers are current; configure Resend/Twilio only if those recovery paths are required.
- [ ] Review logs for startup/schema errors after deployment and verify the health endpoint and main workflows from a browser.

## WhatsApp and Maps

The current environment example contains placeholder names for WhatsApp and Maps configuration. Their presence does not mean live sending or map services are fully integrated.

- WhatsApp: use Meta's official WhatsApp Cloud API. Implement and test message sending, template handling, delivery-status webhooks, consent/opt-out handling, and retry/idempotency behavior before enabling customer notifications.
- Maps: restrict browser keys by website and API; keep server-side credentials private. Enable only the Maps/Places/Routes APIs the product actually uses and set usage alerts/quotas.
- Do not make delivery completion depend on a third-party notification provider succeeding. Persist delivery state first and process notifications with retry-safe handling.

## Deployment approach

1. Deploy a reviewed branch to a separate preview/staging service where possible.
2. Validate the database against a verified backup and test with non-production records.
3. Run `npm run check` and the smoke suite against the intended target.
4. Verify health, security headers, login/session behavior, and delivery flows.
5. Promote to production only after database and rollback checks pass.

## Known operational risk

The current app's startup migration attempts to create a unique index on delivery customer/date/meal. Existing duplicate rows can make startup fail. The correct remedy is a reviewed data audit and repair plan, not silently deleting rows or weakening the uniqueness constraint.
