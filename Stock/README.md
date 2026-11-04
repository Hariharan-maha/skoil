# Oil Stock Manager (Render + Neon, free)

Without DATABASE_URL it saves to data/db.json (local testing: `npm install` then `node server.js`).
With DATABASE_URL (Neon Postgres) it saves there, so data survives Render restarts.

Render settings: Build Command `npm install`, Start Command `node server.js`, env var DATABASE_URL.
Default logins admin/admin123, employee/emp123 - change immediately in Masters > Users.
