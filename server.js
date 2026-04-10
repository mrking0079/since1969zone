
import crypto from 'crypto';
import express from 'express';
import helmet from 'helmet';
import rateLimit from 'express-rate-limit';
import path from 'path';
import fs from 'fs';
import { fileURLToPath } from 'url';
import 'dotenv/config';
import pg from 'pg';
const { Pool } = pg;
import { v2 as cloudinary } from 'cloudinary';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false }
});

cloudinary.config({
  cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
  api_key: process.env.CLOUDINARY_API_KEY,
  api_secret: process.env.CLOUDINARY_API_SECRET
});

const app = express();
app.set('trust proxy', 1);

const PORT = process.env.PORT || 3000;
const ADMIN_KEY = process.env.ADMIN_KEY;
const ADMIN_ROUTE = process.env.ADMIN_ROUTE || '/secure-admin-1969';
const ROUND_SECONDS = 60;
const BETTING_CLOSE_SECONDS = 10;
const JOINING_BONUS_AMOUNT = 100;
const DEVICE_SIGNUP_LIMIT = 2;
const DEVICE_BONUS_LIMIT = 2;
const BONUS_COOLDOWN_MS = 24 * 60 * 60 * 1000;
const DAILY_BONUS_MIN = 10;
const DAILY_BONUS_MAX = 50;
const MIN_PLAY_BEFORE_REQUEST = 300;
const MIN_REQUEST_AMOUNT = 250;
const PAYOUT_MULTIPLIER = 8;
const DEMO_USER_ID = 1;
const DELETED_USERS_FILE = path.join(__dirname, 'deleted-users.json');
const CHAT_MESSAGE_MAX_LENGTH = 220;
const CHAT_FETCH_LIMIT = 40;
const CHAT_REACTIONS = ['👍','❤️','😂','🔥'];

app.use(helmet({ contentSecurityPolicy: false }));
app.use(express.json({ limit: '20mb' }));
app.use(rateLimit({
  windowMs: 60 * 1000,
  max: 5000,
  standardHeaders: true,
  legacyHeaders: false
}));

const adminLoginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 5,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Too many admin login attempts. Try again later.' }
});

app.use(express.static(path.join(__dirname, 'public')));

app.get(ADMIN_ROUTE, (req, res) => {
  const key = String(req.query.key || '').trim();
  if (!ADMIN_KEY || key !== ADMIN_KEY) {
    return res.status(404).send('Not found');
  }
  return res.sendFile(path.join(__dirname, 'public', 'admin.html'));
});

app.get('/admin.html', (req, res) => {
  return res.status(404).send('Not found');
});

app.get('/admin', (req, res) => {
  return res.status(404).send('Not found');
});

app.get('/healthz', async (req, res) => {
  try {
    await pool.query('SELECT 1');
    return res.status(200).json({ ok: true });
  } catch (error) {
    return res.status(500).json({ ok: false });
  }
});

function nowMs() {
  return Date.now();
}

function sha256(value) {
  return crypto.createHash('sha256').update(value).digest('hex');
}

function randomHex(size = 32) {
  return crypto.randomBytes(size).toString('hex');
}

function sanitizeDeviceFingerprint(value) {
  return String(value || '').trim().slice(0, 200);
}

async function ensureDeviceColumnsReady() {
  await pool.query(`
    ALTER TABLE users ADD COLUMN IF NOT EXISTS device_fingerprint TEXT DEFAULT '';
    ALTER TABLE users ADD COLUMN IF NOT EXISTS signup_bonus_given BOOLEAN DEFAULT FALSE;
  `);

  await pool.query(`
    UPDATE users
    SET
      device_fingerprint = COALESCE(device_fingerprint, ''),
      signup_bonus_given = COALESCE(signup_bonus_given, FALSE)
  `);
}

async function getDeviceSignupStats(deviceFingerprint) {
  const safeFingerprint = sanitizeDeviceFingerprint(deviceFingerprint);
  if (!safeFingerprint) {
    return { totalAccounts: 0, bonusAccounts: 0 };
  }

  const result = await pool.query(
    `SELECT
      COUNT(*)::int AS total_accounts,
      COUNT(*) FILTER (WHERE COALESCE(signup_bonus_given, FALSE) = TRUE)::int AS bonus_accounts
     FROM users
     WHERE device_fingerprint = $1 AND is_admin = FALSE`,
    [safeFingerprint]
  );

  return {
    totalAccounts: Number(result.rows[0]?.total_accounts || 0),
    bonusAccounts: Number(result.rows[0]?.bonus_accounts || 0)
  };
}


function hashPassword(password) {
  return sha256(`secure-live-game-password:${String(password || '')}`);
}

function isPasswordMatch(user, plainPassword) {
  const entered = String(plainPassword || '');
  const stored = String(user?.password || '');
  if (!stored) return false;
  if (stored.startsWith('sha256$')) {
    return stored === `sha256$${hashPassword(entered)}`;
  }
  return stored === entered;
}

function jsonParseSafe(value, fallback) {
  try {
    return JSON.parse(value);
  } catch {
    return fallback;
  }
}


function sanitizeChatMessage(value) {
  return String(value || '')
    .replace(/[