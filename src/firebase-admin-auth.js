import { cert, getApps, initializeApp } from 'firebase-admin/app';
import { getAuth } from 'firebase-admin/auth';

const firebaseAuthByApp = new Map();

export function getFirebaseAuth(appId = 'indoone') {
  const normalizedAppId = String(appId || '').trim().toLowerCase();
  if (normalizedAppId !== 'indoone') {
    throw new Error('Firebase Admin authentication is not configured for this app.');
  }

  if (firebaseAuthByApp.has(normalizedAppId)) {
    return firebaseAuthByApp.get(normalizedAppId);
  }

  const projectId = String(process.env.FIREBASE_INDOONE_PROJECT_ID || '').trim();
  const clientEmail = String(process.env.FIREBASE_INDOONE_CLIENT_EMAIL || '').trim();
  const privateKey = String(process.env.FIREBASE_INDOONE_PRIVATE_KEY || '').replace(/\\n/g, '\n').trim();

  if (!projectId || !clientEmail || !privateKey) {
    throw new Error('Indoone Firebase Admin credentials are not configured on the verification server.');
  }

  const appName = 'indoone-verification-auth';
  const app = getApps().find(candidate => candidate.name === appName)
    ?? initializeApp(
      { credential: cert({ projectId, clientEmail, privateKey }) },
      appName,
    );

  const auth = getAuth(app);
  firebaseAuthByApp.set(normalizedAppId, auth);
  return auth;
}
