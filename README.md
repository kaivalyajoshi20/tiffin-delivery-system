# Tiffin Delivery System — Production V1

Staff-only tiffin delivery management system.

## V1 backend
- Node.js + Express + PostgreSQL/Neon
- Staff authentication and roles
- Customers and scalable customer records
- Recurring deliveries and automatic daily generation
- Multiple delivery boys and duty status
- Empty-tiffin and delivered-tiffin proof photos with GPS
- Delivery workflow enforcement
- Coordinate-based automatic route optimization foundation
- Leaves
- WhatsApp notification trigger/status foundation
- Maps-ready customer coordinates and route data

## Required production configuration
Set DATABASE_URL and a strong SESSION_SECRET. Add Google Maps and WhatsApp provider credentials only after the client supplies the relevant accounts/access.

## Local run
npm install
npm start

Open http://localhost:3000.
