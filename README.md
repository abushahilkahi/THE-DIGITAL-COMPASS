# Computer Center Admission Portal

A production-oriented starter portal with:
- Student registration from anywhere on the internet once deployed.
- Fixed admission fee of ₹1000.
- Payment QR shown after application submission (the supplied QR image is `public/payment-qr.png`).
- Admin login and application dashboard.
- Admin payment verification.
- Admin approve/reject workflow.
- Automatic Student ID and random password after approval.
- Student login and password change.
- SQLite database, bcrypt password hashing, JWT authentication and rate-limited login endpoints.

## Run locally
1. Install Node.js 20+.
2. Copy `.env.example` to `.env`.
3. Set a long random `JWT_SECRET`.
4. Run `npm install`.
5. Run `npm start`.
6. Open `http://localhost:3000`.

The initial admin credentials are read from `.env` (`ADMIN_ID` and `ADMIN_PASSWORD`). Change them before production use.

## Important payment note
The QR code is displayed and students can enter a transaction ID. The portal intentionally does **not** treat a transaction ID as proof of payment. Admin must verify payment before/alongside approving the application. For automatic payment confirmation, connect a real payment gateway/webhook (Razorpay/PhonePe/PayU/etc.) and verify signatures server-side.

## Deploy for worldwide access
Deploy the Node app to a public HTTPS host (Render, Railway, Fly.io, VPS, etc.) with a persistent disk for `center.db`. Set environment variables there. For a multi-instance production deployment, use PostgreSQL instead of SQLite.

## Security
Do not publish `.env`, database files, admin credentials, or student passwords. Use HTTPS, a strong JWT secret, regular backups, and a real email/SMS/WhatsApp provider if credentials should be delivered automatically. The generated password is shown to the admin once; it is hashed in the database.
