# Tiffin Delivery System

Staff-only tiffin delivery management system.

## Stack

- Node.js
- Express
- PostgreSQL / Neon
- HTML/CSS/JavaScript
- Render

## Development

1. Copy `.env.example` to `.env`.
2. Set `DATABASE_URL` to the Neon PostgreSQL connection string.
3. Run `npm install`.
4. Run `npm start`.

Health check: `GET /api/health`

Authentication, customer management, delivery workflows, GPS/photo proof, route planning, and WhatsApp notifications will be added incrementally.
