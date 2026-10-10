# DABBA DOPE — Staff Tiffin Delivery Management

Staff-only tiffin delivery management system.

## Stack
- Node.js + Express
- PostgreSQL
- Vanilla JavaScript frontend
- express-session with PostgreSQL session storage, CSRF protection, Helmet, and database-backed API rate limits

## Current functionality
- Staff authentication and role-based access
- Customer records with 7-, 15-, or 30-day delivery-cycle selection when creating a customer
- Delivery creation and status tracking
- Driver roster with manually entered custom email addresses
- Empty-tiffin and delivered-tiffin proof photos with GPS
- Driver route optimization foundation and map links
- Admin notifications, including driver password-reset events
- Admin password recovery by email OTP and driver recovery by SMS OTP (requires provider configuration)
- History reports for the last 7, 15, or 30 days, printable through the browser's Print / Save PDF dialog and downloadable as CSV
- Leave management and WhatsApp notification integration foundation

## Required production configuration
- `DATABASE_URL`: PostgreSQL connection string
- `SESSION_SECRET`: at least 32 characters of high-entropy random data
- `PGSSL_CA` when the database provider requires a custom CA certificate; otherwise use the provider's standard verified TLS setup

### Password recovery providers (optional until configured)
- Admin email OTP: `RESEND_API_KEY` and `RESET_EMAIL_FROM`
- Driver SMS OTP: `TWILIO_ACCOUNT_SID`, `TWILIO_AUTH_TOKEN`, and `TWILIO_FROM_NUMBER`
- Admin user must have a valid registered email; driver must have a valid mobile number in international format for SMS delivery.

Never commit provider credentials to the repository. Set them in the hosting provider's environment settings. Recovery requests intentionally return a generic response to avoid revealing whether a staff ID exists.

### Optional demo accounts
Demo accounts are disabled unless `DEMO_ACCOUNTS_ENABLED=true`. To enable them, configure all of the following in the hosting provider's environment settings:
- `DEMO_ACCOUNTS_ENABLED=true`
- `DEMO_ADMIN_USERNAME` and `DEMO_ADMIN_PASSWORD`
- `DEMO_DRIVER_USERNAME` and `DEMO_DRIVER_PASSWORD`
- Optional display names: `DEMO_ADMIN_NAME` and `DEMO_DRIVER_NAME`

Use distinct usernames and strong passwords of 12–200 characters. At startup, the app creates missing accounts with bcrypt hashes (cost 12); it never resets passwords or overwrites profiles for existing usernames. A username that already exists with a different role causes startup to fail rather than changing its privileges. Disable demo accounts by setting `DEMO_ACCOUNTS_ENABLED=false`; this does not delete accounts already created, so deactivate or remove them deliberately through a controlled database/admin process when they are no longer needed.

**Security:** the demo admin has the app's full admin permissions. Enable these accounts only against a dedicated demo database populated with synthetic data, not a database containing real customer or staff data. Demo accounts are ordinary database users and should be disabled or removed when testing is complete. Never commit passwords to the repository.


## Legacy recurring-delivery schema
The old recurring-delivery tables/columns are retained for backward compatibility with existing production data. The user-facing recurring-delivery creation controls are removed; do not drop legacy tables or columns until production data has been backed up and audited.

## Local run
```sh
npm install
npm start
```

Open http://localhost:3000.

## Checks
```sh
npm run check
npm run test:smoke
```

The smoke tests target the configured live app; run them deliberately after deployment and verify the correct environment before doing so.
