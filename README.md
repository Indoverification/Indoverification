# IndoVerification

Reusable email OTP authentication API.

## API endpoints

### Authentication
- POST /api/auth/signup/request-otp
- POST /api/auth/signup/verify-otp
- POST /api/auth/login/request-otp
- POST /api/auth/login/verify-otp
- POST /api/auth/resend-otp
- POST /api/auth/forgot-password/request-otp
- POST /api/auth/forgot-password/verify-otp

### OTP-protected account actions
All account-action endpoints require `Authorization: Bearer <token>`.

- POST /api/account/activate/request-otp
- POST /api/account/activate/verify-otp
- POST /api/account/deactivate/request-otp
- POST /api/account/deactivate/verify-otp
- POST /api/account/delete/request-otp
- POST /api/account/delete/verify-otp

### Health
- GET /health

## Setup
Use Node.js 20+. Run `npm install`, configure the variables shown in `.env.example`, then run `npm start`.

OTP codes are generated and verified on the server. OTP values are hashed before storage, have an expiry, resend cooldown, and maximum-attempt limit. SMTP credentials stay in environment variables and must never be committed to the repository.

## Indoone email-OTP login session

For the Indoone app, a successful `POST /api/auth/login/verify-otp` response also contains a short-lived Firebase custom token. The Android client exchanges that token with Firebase Authentication so OTP login creates a real Firebase user session. Firebase Admin credentials stay in the deployment environment and must never be committed.
