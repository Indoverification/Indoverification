import http from 'node:http';
import crypto from 'node:crypto';
import fs from 'node:fs';
import pg from 'pg';
import 'dotenv/config';
import { getAppConfig, listApps, DEFAULT_APP_ID, appRoot } from './app-registry.js';
import { resolveAppContext, appIdForOrigin, APP_ID_HEADER, LEGACY_APP_HEADER } from './app-request.js';
import { sendMail } from './mail-service.js';
import { getFirebaseAuth } from './firebase-admin-auth.js';

const { Pool } = pg;
const PORT = Number(process.env.PORT || 10000);
const HOST = '0.0.0.0';
const DATABASE_URL = String(process.env.DATABASE_URL || '').trim();
const OTP_TTL_MS = Math.max(60, Number(process.env.OTP_TTL_SECONDS || 600)) * 1000;
const OTP_RESEND_MS = Math.max(15, Number(process.env.OTP_RESEND_SECONDS || 60)) * 1000;
const OTP_MAX_ATTEMPTS = Math.max(1, Number(process.env.OTP_MAX_ATTEMPTS || 5));
const WELCOME_TOKEN_TTL_MS = 15 * 60 * 1000;

if (!DATABASE_URL) throw new Error('DATABASE_URL is required.');
const pool = new Pool({
  connectionString: DATABASE_URL,
  ssl: String(process.env.PGSSL || 'false') === 'true' ? { rejectUnauthorized: false } : undefined,
  max: 10,
  idleTimeoutMillis: 30000,
  connectionTimeoutMillis: 10000,
});

let dbReady = false;

function sendJson(res, status, body) {
  res.statusCode = status;
  res.setHeader('Content-Type', 'application/json; charset=utf-8');
  res.setHeader('Cache-Control', 'no-store');
  res.end(JSON.stringify(body));
}

function appFromRequest(req, body = {}) {
  return resolveAppContext({ body, headers: req.headers, origin: req.headers.origin });
}

function setCors(res, req) {
  const origin = String(req.headers.origin || '').trim();
  let appId = String(req.headers[APP_ID_HEADER] || req.headers[LEGACY_APP_HEADER] || '').trim().toLowerCase();
  if (!appId && origin) appId = appIdForOrigin(origin);

  let allowOrigin = '';
  if (appId) {
    try { allowOrigin = new URL(getAppConfig(appId).url).origin; } catch {}
  }

  if (origin === 'null' && allowOrigin) res.setHeader('Access-Control-Allow-Origin', '*');
  else if (origin && allowOrigin && origin === allowOrigin) res.setHeader('Access-Control-Allow-Origin', origin);
  else if (!origin && allowOrigin) res.setHeader('Access-Control-Allow-Origin', allowOrigin);

  res.setHeader('Vary', 'Origin');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization, X-Indo-App-Id, X-Indo-App-Name');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
}

async function readBody(req) {
  let raw = '';
  for await (const chunk of req) {
    raw += chunk;
    if (raw.length > 1_000_000) throw new Error('Request too large');
  }
  if (!raw) return {};
  try { return JSON.parse(raw); } catch { throw new Error('Invalid JSON'); }
}

function email(value) {
  return String(value || '').normalize('NFKC').replace(/[\u0000-\u001F\u007F\u00A0\u200B-\u200D\u2060\uFEFF]/g, '').trim().toLowerCase();
}
function validEmail(value) { return /^[A-Z0-9.!#$%&'*+/=?^_`{|}~-]+@[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?(?:\.[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?)+$/i.test(email(value)); }
function normalizeOtp(value) { return String(value || '').normalize('NFKC').replace(/[^0-9]/g, '').slice(0, 6); }
function generateOtp() { return String(crypto.randomInt(100000, 1000000)); }
function generateToken(bytes = 24) { return crypto.randomBytes(bytes).toString('hex'); }
function hash(value) { return crypto.createHash('sha256').update(String(value)).digest('hex'); }
function sameHash(a, b) {
  const left = Buffer.from(String(a), 'hex');
  const right = Buffer.from(String(b), 'hex');
  return left.length === right.length && left.length > 0 && crypto.timingSafeEqual(left, right);
}
function escapeHtml(value) {
  return String(value ?? '').replaceAll('&', '&amp;').replaceAll('<', '&lt;').replaceAll('>', '&gt;').replaceAll('"', '&quot;').replaceAll("'", '&#39;');
}

function loadBrand(appId) {
  const root = appRoot(appId);
  const manifestPath = `${root}/email-templates.json`;
  const fallback = {
    appId,
    templates: {
      signupOtp: 'signup-otp',
      loginOtp: 'login-otp',
      welcome: 'welcome',
      welcomeBack: 'welcome-back',
    },
    branding: {
      name: getAppConfig(appId).name,
      logoAsset: 'logo.svg',
      primaryColor: '#2563EB',
    },
  };
  try {
    const value = JSON.parse(fs.readFileSync(manifestPath, 'utf8'));
    return { ...fallback, ...value, templates: { ...fallback.templates, ...(value.templates || {}) }, branding: { ...fallback.branding, ...(value.branding || {}) } };
  } catch {
    return fallback;
  }
}

function renderAppTemplate(appId, templateKey, variables = {}) {
  const brand = loadBrand(appId);
  const templateName = String(brand.templates?.[templateKey] || '').trim();
  if (!templateName) throw new Error(`Missing email template mapping: ${templateKey}`);
  if (!/^[a-z0-9][a-z0-9_-]*$/i.test(templateName)) throw new Error('Invalid email template name.');

  const templatePath = `${appRoot(appId)}/templates/${templateName}.html`;
  let html;
  try {
    html = fs.readFileSync(templatePath, 'utf8');
  } catch {
    throw new Error(`Missing email template file: ${templateName}.html`);
  }

  const values = {
    appName: brand.branding.name || getAppConfig(appId).name,
    primaryColor: brand.branding.primaryColor || '#2563EB',
    minutes: Math.round(OTP_TTL_MS / 60000),
    ...variables,
  };
  return html.replace(/{{\s*([a-zA-Z0-9_]+)\s*}}/g, (_, key) => escapeHtml(values[key] ?? ''));
}

async function mailOtp(appId, to, code, kind) {
  const brand = loadBrand(appId);
  const name = brand.branding.name || getAppConfig(appId).name;
  const normalizedKind = String(kind || 'login');
  const templateKey = normalizedKind === 'signup' ? 'signupOtp' : normalizedKind === 'forgotPassword' ? 'forgotPasswordOtp' : 'loginOtp';
  const subject = normalizedKind === 'signup'
    ? `${name} • Verify your email`
    : normalizedKind === 'forgotPassword'
      ? `${name} • Password reset verification code`
      : `${name} • Login verification code`;
  const content = renderAppTemplate(appId, templateKey, { code });
  await sendMail({ to, subject, html: content });
}

async function mailNewAccountWelcome(appId, to, nameValue) {
  const brand = loadBrand(appId);
  const name = brand.branding.name || getAppConfig(appId).name;
  const content = renderAppTemplate(appId, 'welcome', { recipientName: nameValue || 'there' });
  await sendMail({ to, subject: `${name} • Welcome — your account is ready`, html: content });
}

async function mailWelcomeBack(appId, to, nameValue) {
  const brand = loadBrand(appId);
  const name = brand.branding.name || getAppConfig(appId).name;
  const content = renderAppTemplate(appId, 'welcomeBack', { recipientName: nameValue || 'there' });
  await sendMail({ to, subject: `${name} • Welcome back — login successful`, html: content });
}

async function initDb() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS otp_codes (
      otp_key TEXT PRIMARY KEY,
      app_id TEXT NOT NULL DEFAULT 'indomark',
      email TEXT NOT NULL,
      purpose TEXT NOT NULL,
      code_hash TEXT NOT NULL,
      sent_at TIMESTAMPTZ NOT NULL,
      expires_at TIMESTAMPTZ NOT NULL,
      attempts INTEGER NOT NULL DEFAULT 0,
      challenge_id TEXT
    );
    ALTER TABLE otp_codes ADD COLUMN IF NOT EXISTS app_id TEXT;
    UPDATE otp_codes SET app_id='indomark' WHERE app_id IS NULL;
    ALTER TABLE otp_codes ALTER COLUMN app_id SET DEFAULT 'indomark';
    ALTER TABLE otp_codes ALTER COLUMN app_id SET NOT NULL;
    CREATE UNIQUE INDEX IF NOT EXISTS otp_codes_challenge_id_uq ON otp_codes(challenge_id) WHERE challenge_id IS NOT NULL;
    CREATE INDEX IF NOT EXISTS otp_codes_app_email_purpose_sent_idx ON otp_codes(app_id,email,purpose,sent_at DESC);

    CREATE TABLE IF NOT EXISTS signup_welcome_tokens (
      token_hash TEXT PRIMARY KEY,
      app_id TEXT NOT NULL DEFAULT 'indomark',
      email TEXT NOT NULL,
      name TEXT NOT NULL,
      created_at TIMESTAMPTZ NOT NULL,
      expires_at TIMESTAMPTZ NOT NULL,
      used_at TIMESTAMPTZ
    );
    ALTER TABLE signup_welcome_tokens ADD COLUMN IF NOT EXISTS app_id TEXT;
    UPDATE signup_welcome_tokens SET app_id='indomark' WHERE app_id IS NULL;
    ALTER TABLE signup_welcome_tokens ALTER COLUMN app_id SET DEFAULT 'indomark';
    ALTER TABLE signup_welcome_tokens ALTER COLUMN app_id SET NOT NULL;
    CREATE INDEX IF NOT EXISTS signup_welcome_tokens_app_email_idx ON signup_welcome_tokens(app_id,email,created_at DESC);
    DELETE FROM otp_codes WHERE expires_at < NOW();
    DELETE FROM signup_welcome_tokens WHERE expires_at < NOW();
  `);
}

async function issueOtp(appId, emailAddress, purpose) {
  const recipient = email(emailAddress);
  const latest = await pool.query('SELECT sent_at FROM otp_codes WHERE app_id=$1 AND email=$2 AND purpose=$3 ORDER BY sent_at DESC LIMIT 1', [appId, recipient, purpose]);
  const now = new Date();
  if (latest.rows[0] && now.getTime() - new Date(latest.rows[0].sent_at).getTime() < OTP_RESEND_MS) throw new Error('Please wait before requesting another OTP.');
  await pool.query('DELETE FROM otp_codes WHERE app_id=$1 AND email=$2 AND purpose=$3', [appId, recipient, purpose]);
  const code = generateOtp();
  const challenge = generateToken();
  await pool.query('INSERT INTO otp_codes (otp_key,app_id,email,purpose,code_hash,sent_at,expires_at,attempts,challenge_id) VALUES ($1,$2,$3,$4,$5,$6,$7,0,$1)', [challenge, appId, recipient, purpose, hash(code), now, new Date(now.getTime() + OTP_TTL_MS)]);
  try { await mailOtp(appId, recipient, code, purpose); }
  catch (error) { await pool.query('DELETE FROM otp_codes WHERE otp_key=$1', [challenge]).catch(() => {}); throw error; }
  return challenge;
}

async function verifyOtp(appId, challengeId, emailAddress, submittedOtp) {
  const key = String(challengeId || '').trim();
  const recipient = email(emailAddress);
  const result = await pool.query('SELECT * FROM otp_codes WHERE challenge_id=$1 AND app_id=$2 AND email=$3 LIMIT 1', [key, appId, recipient]);
  const item = result.rows[0];
  if (!item) throw new Error('OTP not found or expired.');
  if (Date.now() > new Date(item.expires_at).getTime()) { await pool.query('DELETE FROM otp_codes WHERE otp_key=$1', [item.otp_key]); throw new Error('OTP expired.'); }
  if (item.attempts >= OTP_MAX_ATTEMPTS) { await pool.query('DELETE FROM otp_codes WHERE otp_key=$1', [item.otp_key]); throw new Error('Too many incorrect attempts.'); }
  const submitted = normalizeOtp(submittedOtp);
  if (!/^\d{6}$/.test(submitted) || !sameHash(hash(submitted), item.code_hash)) {
    await pool.query('UPDATE otp_codes SET attempts=attempts+1 WHERE otp_key=$1', [item.otp_key]);
    throw new Error('Invalid OTP.');
  }
  await pool.query('DELETE FROM otp_codes WHERE otp_key=$1', [item.otp_key]);
  return item;
}

async function createSignupWelcomeToken(appId, emailAddress, name) {
  const recipient = email(emailAddress);
  const token = generateToken();
  await pool.query('DELETE FROM signup_welcome_tokens WHERE app_id=$1 AND email=$2 AND used_at IS NULL', [appId, recipient]);
  await pool.query('INSERT INTO signup_welcome_tokens (token_hash,app_id,email,name,created_at,expires_at) VALUES ($1,$2,$3,$4,NOW(),$5)', [hash(token), appId, recipient, String(name || '').trim(), new Date(Date.now() + WELCOME_TOKEN_TTL_MS)]);
  return token;
}

async function consumeSignupWelcomeToken(appId, token, emailAddress, name) {
  const recipient = email(emailAddress);
  const tokenHash = hash(token);
  const result = await pool.query('SELECT * FROM signup_welcome_tokens WHERE token_hash=$1 AND app_id=$2 AND email=$3 LIMIT 1', [tokenHash, appId, recipient]);
  const item = result.rows[0];
  if (!item || item.used_at) throw new Error('Welcome email authorization expired.');
  if (Date.now() > new Date(item.expires_at).getTime()) {
    await pool.query('DELETE FROM signup_welcome_tokens WHERE token_hash=$1', [tokenHash]);
    throw new Error('Welcome email authorization expired.');
  }
  await mailNewAccountWelcome(appId, recipient, String(name || item.name || 'there').trim());
  await pool.query('UPDATE signup_welcome_tokens SET used_at=NOW() WHERE token_hash=$1 AND used_at IS NULL', [tokenHash]);
}

async function main(req, res) {
  setCors(res, req);
  if (req.method === 'OPTIONS') return sendJson(res, 204, {});
  const url = new URL(req.url || '/', `http://${req.headers.host || 'localhost'}`);
  try {
    if (url.pathname === '/health' && req.method === 'GET') {
      return sendJson(res, 200, { ok: true, ready: dbReady, service: 'IndoVerification', role: 'multi-app OTP service', apps: listApps().map(({ id, name }) => ({ id, name })), emailConfigured: true, time: new Date().toISOString() });
    }

    if (!dbReady) return sendJson(res, 503, { ok: false, error: 'Service is starting. Please retry in a moment.' });

    const body = await readBody(req);
    const context = appFromRequest(req, body);
    const appId = context.appId;

    if (url.pathname === '/api/auth/signup/request-otp' && req.method === 'POST') {
      const e = email(body.email); const name = String(body.name || '').trim();
      if (!name || !validEmail(e)) return sendJson(res, 400, { ok: false, error: 'Name and a valid email are required.' });
      const challengeId = await issueOtp(appId, e, 'signup');
      return sendJson(res, 200, { ok: true, message: 'OTP sent to your email.', challengeId, appId });
    }

    if (url.pathname === '/api/auth/signup/verify-otp' && req.method === 'POST') {
      const e = email(body.email); if (!validEmail(e)) return sendJson(res, 400, { ok: false, error: 'Enter a valid email.' });
      const verification = await verifyOtp(appId, body.challengeId, e, body.otp);
      if (verification.purpose !== 'signup') return sendJson(res, 400, { ok: false, error: 'OTP request mismatch.' });
      const name = String(body.name || '').trim(); const welcomeToken = await createSignupWelcomeToken(appId, e, name);
      return sendJson(res, 200, { ok: true, verified: true, email: e, name, welcomeToken, appId });
    }

    if (url.pathname === '/api/auth/signup/welcome' && req.method === 'POST') {
      const e = email(body.email); if (!validEmail(e)) return sendJson(res, 400, { ok: false, error: 'Enter a valid email.' });
      await consumeSignupWelcomeToken(appId, body.welcomeToken, e, String(body.name || '').trim());
      return sendJson(res, 200, { ok: true, welcomeSent: true, appId });
    }

    if (url.pathname === '/api/auth/login/request-otp' && req.method === 'POST') {
      const e = email(body.email); if (!validEmail(e)) return sendJson(res, 400, { ok: false, error: 'Enter a valid email.' });
      const challengeId = await issueOtp(appId, e, 'login');
      return sendJson(res, 200, { ok: true, message: 'OTP sent to your email.', challengeId, appId });
    }

    if (url.pathname === '/api/auth/login/verify-otp' && req.method === 'POST') {
      const e = email(body.email); if (!validEmail(e)) return sendJson(res, 400, { ok: false, error: 'Enter a valid email.' });
      const verification = await verifyOtp(appId, body.challengeId, e, body.otp);
      if (verification.purpose !== 'login') return sendJson(res, 400, { ok: false, error: 'OTP request mismatch.' });

      let customToken = '';
      if (appId === 'indoone') {
        const auth = getFirebaseAuth(appId);
        const user = await auth.getUserByEmail(e);
        customToken = await auth.createCustomToken(user.uid, {
          app_id: appId,
          auth_method: 'email_otp',
        });
      }

      let welcomeSent = true;
      try { await mailWelcomeBack(appId, e, String(body.name || '').trim()); } catch (error) { welcomeSent = false; console.error('Welcome-back email failed:', error instanceof Error ? error.message : error); }

      return sendJson(res, 200, {
        ok: true,
        verified: true,
        email: e,
        welcomeSent,
        appId,
        ...(customToken ? { customToken } : {}),
      });
    }

    if (url.pathname === '/api/auth/resend-otp' && req.method === 'POST') {
      const e = email(body.email); const purpose = String(body.purpose || 'signup');
      if (!validEmail(e)) return sendJson(res, 400, { ok: false, error: 'Enter a valid email.' });
      if (!['signup', 'login'].includes(purpose)) return sendJson(res, 400, { ok: false, error: 'Invalid OTP purpose.' });
      const challengeId = await issueOtp(appId, e, purpose);
      return sendJson(res, 200, { ok: true, message: 'OTP resent.', challengeId, appId });
    }

    if (url.pathname === '/api/auth/forgot-password/request-otp' && req.method === 'POST') {
      const e = email(body.email);
      if (!validEmail(e)) return sendJson(res, 400, { ok: false, error: 'Enter a valid email.' });
      const challengeId = await issueOtp(appId, e, 'forgotPassword');
      return sendJson(res, 200, { ok: true, message: 'OTP sent to your email.', challengeId, appId });
    }

    if (url.pathname === '/api/auth/forgot-password/verify-otp' && req.method === 'POST') {
      const e = email(body.email);
      if (!validEmail(e)) return sendJson(res, 400, { ok: false, error: 'Enter a valid email.' });
      const verification = await verifyOtp(appId, body.challengeId, e, body.otp);
      if (verification.purpose !== 'forgotPassword') return sendJson(res, 400, { ok: false, error: 'OTP request mismatch.' });
      return sendJson(res, 200, { ok: true, verified: true, email: e, appId });
    }

    return sendJson(res, 404, { ok: false, error: 'Not found' });
  } catch (error) {
    console.error('REQUEST ERROR:', error);
    const message = error instanceof Error ? error.message : 'Server error';
    const status = /Zoho Mail API|Zoho token|Zoho Mail send|configured Zoho sender|recipient email address/i.test(message) ? 503 : 400;
    return sendJson(res, status, { ok: false, error: message });
  }
}

const server = http.createServer(main);
server.listen(PORT, HOST, () => {
  console.log(`IndoVerification multi-app service listening on ${HOST}:${PORT}`);
  initDb().then(() => {
    dbReady = true;
    console.log('IndoVerification database ready');
  }).catch((error) => {
    dbReady = false;
    console.error('Database startup failed:', error);
  });
});
