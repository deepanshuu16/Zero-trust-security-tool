# Zero Trust Security Tool

SecureU zero-trust security platform with:

- backend-generated OTP verification
- Resend email delivery
- Twilio WhatsApp delivery
- hashed single-use OTP storage with expiry, resend cooldown, rate limits, and attempt caps
- role-based access after verification

## Run

```bash
npm install
npm start
```

Then open `http://localhost:3000`.

## Environment

Copy `.env.example` to `.env` locally or add the values in Vercel Project Settings.

Required production values include:

- `RESEND_API_KEY`
- `EMAIL_FROM`
- `TWILIO_ACCOUNT_SID` or `TWILIO_SID`
- `TWILIO_AUTH_TOKEN`
- `TWILIO_WHATSAPP_FROM`
- `MONGODB_URI`
- `REDIS_URL`
- `JWT_SECRET`
- `OTP_SECRET`

## Notes

- OTPs are generated only on the backend.
- OTPs are never returned to the browser or shown on screen.
- Production fails closed if real email or WhatsApp providers are not configured.

## Public Deployment

Deploy the Node app to Vercel from the connected GitHub repository. Add the environment variables in Vercel Dashboard -> Project Settings -> Environment Variables before testing login.

Important:

- The app now binds to `0.0.0.0` so it can run on hosting platforms
- Sessions and login activity are currently stored in memory, so they reset when the service restarts
- For a truly production-ready website, the next step is moving sessions, users, and audit logs to a database
