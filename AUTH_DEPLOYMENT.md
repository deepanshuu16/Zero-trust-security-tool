# SecureU OTP Authentication Deployment

## Stack

- Node.js + Express API
- MongoDB with Mongoose for users, sessions, login history, and alerts
- Redis for OTP, resend cooldown, and reset-token storage
- JWT in secure HttpOnly cookies
- bcrypt password hashing
- Nodemailer or SendGrid SMTP for email OTP
- Twilio WhatsApp API with SMS fallback
- Helmet, CSRF, rate limiting, XSS protection, input sanitization, HPP protection, HTTPS enforcement

## Required Environment

Copy `.env.example` to `.env` locally or add the same variables in Vercel.

Important production values:

- `MONGODB_URI`
- `REDIS_URL`
- `JWT_SECRET`
- `OTP_SECRET`
- `SMTP_HOST`, `SMTP_PORT`, `SMTP_USER`, `SMTP_PASS`, `EMAIL_FROM`
- `TWILIO_ACCOUNT_SID`, `TWILIO_AUTH_TOKEN`, `TWILIO_WHATSAPP_FROM`
- `TWILIO_SMS_FROM` for SMS fallback
- `PUBLIC_APP_URL`
- `ALLOWED_ORIGINS`

## API Routes

- `GET /api/csrf-token`
- `POST /api/auth/signup`
- `POST /api/auth/login`
- `POST /api/auth/otp/verify`
- `POST /api/auth/otp/resend`
- `POST /api/auth/forgot-password`
- `POST /api/auth/reset-password`
- `POST /api/auth/logout`
- `GET /api/auth/me`
- `GET /api/security/dashboard`

## OTP Rules

- OTP code length: 6 digits
- OTP validity: 5 minutes
- Resend cooldown: 60 seconds
- Verification attempt cap: 5 failed attempts per OTP
- Rate limits: authentication and OTP routes are separately limited

## Frontend Pages

- `/login.html`
- `/signup.html`
- `/verify-otp.html`
- `/forgot-password.html`
- `/reset-password.html`
- `/dashboard.html`

## Deployment

1. Install dependencies with `npm install`.
2. Set all production environment variables.
3. Start locally with `npm start`.
4. Deploy to Vercel from the connected GitHub repository.
5. Confirm that `/api/csrf-token` returns a token and auth pages can submit forms.

For local development without SMTP or Twilio credentials, OTP values are logged to the server console. Production should always configure real providers.
