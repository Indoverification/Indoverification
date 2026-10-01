// Compatibility entrypoint for the multi-app runtime.
// The legacy server-v2.js remains preserved for rollback/comparison.
import http from 'node:http';
import crypto from 'node:crypto';
import fs from 'node:fs';
import pg from 'pg';
import 'dotenv/config';
import { getFirebaseAuth } from './firebase-admin-auth.js';
import { appRoot } from './app-registry.js';
import { sendMail } from './mail-service.js';

const rawZohoFrom = String(process.env.ZOHO_FROM || '').normalize('NFKC').trim();
const angleMatch = rawZohoFrom.match(/<\s*([^<>\s]+@[^<>\s]+)\s*>/i);
const plainMatch = rawZohoFrom.match(/^["']?\s*([^<>\s]+@[^<>\s]+)\s*["']?$/i);
if (angleMatch?.[1]) process.env.ZOHO_FROM = angleMatch[1].trim().toLowerCase();
else if (plainMatch?.[1]) process.env.ZOHO_FROM = plainMatch[1].trim().toLowerCase();

// Shared browser OTP API; no browser credentials are used.
process.env.CORS_ORIGIN = '*';

const { Pool } = pg;
const DATABASE_URL = String(process.env.DATABASE_URL || '').trim();
const RESET_OTP_TTL_MS = Math.max(60, Number(process.env.FORGOT_PASSWORD_OTP_TTL_SECONDS || 600)) * 1000;
const RESET_OTP_RESEND_MS = Math.max(15, Number(process.env.FORGOT_PASSWORD_OTP_RESEND_SECONDS || 60)) * 1000;
const RESET_OTP_MAX_ATTEMPTS = Math.max(1, Number(process.env.FORGOT_PASSWORD_OTP_MAX_ATTEMPTS || 5));
const RESET_TOKEN_TTL_MS = Math.max(60, Number(process.env.FORGOT_PASSWORD_RESET_TOKEN_TTL_SECONDS || 900)) * 1000;

if (!DATABASE_URL) throw new Error('DATABASE_URL is required.');
const pool = new Pool({
  connectionString: DATABASE_URL,
  ssl: String(process.env.PGSSL || 'false') === 'true' ? { rejectUnauthorized: false } : undefined,
  max: 10,
  idleTimeoutMillis: 30000,
  connectionTimeoutMillis: 10000,
});

let tablesReadyPromise;
function renderForgotPasswordOtp(code) {
  const templatePath = `${appRoot('indoone')}/templates/forgot-password-otp.html`;
  let html = fs.readFileSync(templatePath, 'utf8');
  html = html.replace(/{{\s*code\s*}}/g, code);
  html = html.replace(/{{\s*minutes\s*}}/g, String(Math.round(RESET_OTP_TTL_MS / 60000)));
  html = html.replace(/{{\s*appName\s*}}/g, 'Indoone');
  return html;
}

async function issueRecoveryOtp(appId, recipient) {
  await ensureRecoveryTables();
  const latest = await pool.query(
    'SELECT sent_at FROM forgot_password_otps WHERE app_id=$1 AND email=$2 ORDER BY sent_at DESC LIMIT 1',
    [appId, recipient]
  );
  const now = new Date();
  if (latest.rows[0] && now.getTime() - new Date(latest.rows[0].sent_at).getTime() < RESET_OTP_RESEND_MS) {
    throw new Error('Please wait before requesting another OTP.');
  }

  await pool.query('DELETE FROM forgot_password_otps WHERE app_id=$1 AND email=$2', [appId, recipient]);
  const code = generateOtp();
  const challengeId = generateToken(24);

  await pool.query(
    'INSERT INTO forgot_password_otps (challenge_id,app_id,email,code_hash,sent_at,expires_at,attempts) VALUES ($1,$2,$3,$4,$5,$6,0)',
    [challengeId, appId, recipient, hash(code), now, new Date(now.getTime() + RESET_OTP_TTL_MS)]
  );

  try {
    await sendMail({
      to: recipient,
      subject: 'Indoone • Password reset verification code',
      html: renderForgotPasswordOtp(code),
    });
  } catch (error) {
    await pool.query('DELETE FROM forgot_password_otps WHERE challenge_id=$1', [challengeId]).catch(() => {});
    throw error;
  }

  return challengeId;
}

async function verifyRecoveryOtp(appId, recipient, challengeId, submittedOtp) {
  await ensureRecoveryTables();
  const result = await pool.query(
    'SELECT * FROM forgot_password_otps WHERE challenge_id=$1 AND app_id=$2 AND email=$3 LIMIT 1',
    [String(challengeId || '').trim(), appId, recipient]
  );
  const item = result.rows[0];
  if (!item) throw new Error('OTP not found or expired.');
  if (Date.now() > new Date(item.expires_at).getTime()) {
    await pool.query('DELETE FROM forgot_password_otps WHERE challenge_id=$1', [item.challenge_id]);
    throw new Error('OTP expired.');
  }
  if (item.attempts >= RESET_OTP_MAX_ATTEMPTS) {
    await pool.query('DELETE FROM forgot_password_otps WHERE challenge_id=$1', [item.challenge_id]);
    throw new Error('Too many incorrect attempts.');
  }

  const submitted = normalizeOtp(submittedOtp);
  if (!/^\d{6}$/.test(submitted) || !sameHash(hash(submitted), item.code_hash)) {
    await pool.query('UPDATE forgot_password_otps SET attempts=attempts+1 WHERE challenge_id=$1', [item.challenge_id]);
    throw new Error('Invalid OTP.');
  }

  await pool.query('DELETE FROM forgot_password_otps WHERE challenge_id=$1', [item.challenge_id]);
  return item;
}

async function createResetToken(appId, recipient, uid) {
  await ensureRecoveryTables();
  const token = generateToken(32);
  await pool.query('DELETE FROM forgot_password_reset_tokens WHERE app_id=$1 AND email=$2', [appId, recipient]);
  await pool.query(
    'INSERT INTO forgot_password_reset_tokens (token_hash,app_id,email,uid,created_at,expires_at) VALUES ($1,$2,$3,$4,NOW(),$5)',
    [hash(token), appId, recipient, uid, new Date(Date.now() + RESET_TOKEN_TTL_MS)]
  );
  return token;
}

async function consumeResetToken(appId, recipient, token) {
  await ensureRecoveryTables();
  const result = await pool.query(
    'DELETE FROM forgot_password_reset_tokens WHERE token_hash=$1 AND app_id=$2 AND email=$3 AND expires_at > NOW() RETURNING uid',
    [hash(token), appId, recipient]
  );
  const item = result.rows[0];
  if (!item?.uid) throw new Error('Reset authorization expired or invalid.');
  return item.uid;
}

async function handleForgotPasswordRequest(req, res) {
  const url = new URL(req.url || '/', `http://${req.headers.host || 'localhost'}`);
  if (!url.pathname.startsWith('/api/auth/forgot-password/')) return false;
  if (req.method !== 'POST') {
    sendJson(res, 405, { ok: false, error: 'Method not allowed.' });
    return true;
  }

  try {
    const body = await readBody(req);
    const appId = String(body.appId || req.headers['x-indo-app-id'] || 'indoone').trim().toLowerCase();
    if (appId !== 'indoone') {
      sendJson(res, 400, { ok: false, error: 'Invalid app.' });
      return true;
    }

    const recipient = email(body.email);
    if (!validEmail(recipient)) {
      sendJson(res, 400, { ok: false, error: 'Enter a valid email.' });
      return true;
    }

    const auth = getFirebaseAuth(appId);

    if (url.pathname === '/api/auth/forgot-password/request-otp') {
      try {
        await auth.getUserByEmail(recipient);
      } catch (error) {
        if (error?.code === 'auth/user-not-found') {
          sendJson(res, 404, { ok: false, error: 'No Indoone account was found.' });
          return true;
        }
        throw error;
      }

      const challengeId = await issueRecoveryOtp(appId, recipient);
      sendJson(res, 200, { ok: true, message: 'OTP sent to your email.', challengeId, appId });
      return true;
    }

    if (url.pathname === '/api/auth/forgot-password/verify-otp') {
      await verifyRecoveryOtp(appId, recipient, body.challengeId, body.otp);
      const user = await auth.getUserByEmail(recipient);
      const resetToken = await createResetToken(appId, recipient, user.uid);
      sendJson(res, 200, { ok: true, verified: true, resetToken, email: recipient, appId });
      return true;
    }

    if (url.pathname === '/api/auth/forgot-password/reset-password') {
      const newPassword = String(body.newPassword || '');
      if (newPassword.length < 6) {
        sendJson(res, 400, { ok: false, error: 'Password should be at least 6 characters.' });
        return true;
      }
      if (newPassword.length > 4096) {
        sendJson(res, 400, { ok: false, error: 'Password is too long.' });
        return true;
      }

      const uid = await consumeResetToken(appId, recipient, String(body.resetToken || '').trim());
      await auth.updateUser(uid, { password: newPassword });
      sendJson(res, 200, { ok: true, message: 'Password changed successfully.' });
      return true;
    }

    sendJson(res, 404, { ok: false, error: 'Not found' });
    return true;
  } catch (error) {
    console.error('Forgot password request failed:', error);
    sendJson(res, 400, { ok: false, error: error?.message || 'Unable to complete password recovery.' });
    return true;
  }
}

const originalCreateServer = http.createServer.bind(http);
http.createServer = function wrappedCreateServer(...args) {
  const index = typeof args[0] === 'function' ? 0 : 1;
  const listener = args[index];
  if (typeof listener !== 'function') return originalCreateServer(...args);

  const wrappedListener = async (req, res) => {
    if (await handleForgotPasswordRequest(req, res)) return;
    return listener(req, res);
  };

  const nextArgs = [...args];
  nextArgs[index] = wrappedListener;
  return originalCreateServer(...nextArgs);
};

await import('./server-multi-app.js');
