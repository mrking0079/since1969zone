
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
  ssl: { rejectUnauthorized: false },
  max: 5,
  min: 1,
  idleTimeoutMillis: 30000,
  connectionTimeoutMillis: 10000,
  allowExitOnIdle: false
});

cloudinary.config({
  cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
  api_key: process.env.CLOUDINARY_API_KEY,
  api_secret: process.env.CLOUDINARY_API_SECRET
});

const app = express();
pool.on('error', (err) => {
  console.error('PG POOL ERROR:', err);
});
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

app.get('/healthz', (req, res) => {
  return res.status(200).json({ ok: true });
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
    .replace(/[\r\n\t]+/g, ' ')
    .replace(/[\x00-\x1F\x7F]/g, ' ')
    .replace(/\s+/g, ' ')
    .trim()
    .slice(0, CHAT_MESSAGE_MAX_LENGTH);
}

function sanitizeChatReaction(value) {
  const safe = String(value || '').trim();
  return CHAT_REACTIONS.includes(safe) ? safe : '';
}

async function getRecentChatMessages(limit = CHAT_FETCH_LIMIT, includeHidden = false) {
  const safeLimit = Math.max(1, Math.min(Number(limit || CHAT_FETCH_LIMIT), CHAT_FETCH_LIMIT));
  const result = await pool.query(
    `SELECT id, user_id, username, message, reactions, is_hidden, created_at
     FROM global_chat_messages
     WHERE ($1::boolean = TRUE OR is_hidden = FALSE)
     ORDER BY id DESC
     LIMIT $2`,
    [Boolean(includeHidden), safeLimit]
  );

  return result.rows.reverse().map(row => ({
    id: Number(row.id),
    userId: Number(row.user_id),
    username: String(row.username || ''),
    message: String(row.message || ''),
    reactions: toJson(row.reactions, {}),
    isHidden: Boolean(row.is_hidden),
    createdAt: Number(row.created_at || 0)
  }));
}

async function checkChatRateLimit(userId) {
  const result = await pool.query(
    `SELECT COUNT(*)::int AS count
     FROM global_chat_messages
     WHERE user_id = $1 AND created_at >= $2`,
    [userId, nowMs() - 5000]
  );
  return Number(result.rows[0]?.count || 0) < 3;
}

function loadDeletedUsersData() {
  if (!fs.existsSync(DELETED_USERS_FILE)) {
    fs.writeFileSync(DELETED_USERS_FILE, JSON.stringify({ deletedUsers: [] }, null, 2), 'utf8');
    return { deletedUsers: [] };
  }
  try {
    const raw = fs.readFileSync(DELETED_USERS_FILE, 'utf8');
    const parsed = jsonParseSafe(raw, { deletedUsers: [] });
    if (!Array.isArray(parsed.deletedUsers)) parsed.deletedUsers = [];
    return parsed;
  } catch {
    return { deletedUsers: [] };
  }
}

function saveDeletedUsersData(data) {
  fs.writeFileSync(DELETED_USERS_FILE, JSON.stringify(data, null, 2), 'utf8');
}

async function testDB() {
  try {
    const res = await pool.query('SELECT NOW()');
    console.log('DB Connected:', res.rows[0]);
  } catch (err) {
    console.error('DB Error:', err);
  }
}

async function initDatabase() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      id BIGSERIAL PRIMARY KEY,
      username TEXT UNIQUE NOT NULL,
      password TEXT NOT NULL,
      session_token TEXT DEFAULT '',
      wallet_balance NUMERIC DEFAULT 0,
      total_played NUMERIC DEFAULT 0,
      total_wins NUMERIC DEFAULT 0,
      bonus_claimed INTEGER DEFAULT 0,
      last_bonus_time BIGINT DEFAULT 0,
      blocked BOOLEAN DEFAULT FALSE,
      is_admin BOOLEAN DEFAULT FALSE,
      admin_role TEXT DEFAULT 'read_only',
      last_active_at BIGINT DEFAULT 0,
      created_at BIGINT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS admin_activity_logs (
      id BIGSERIAL PRIMARY KEY,
      admin_user_id BIGINT NOT NULL,
      admin_username TEXT NOT NULL,
      action TEXT NOT NULL,
      target_user_id BIGINT,
      target_username TEXT DEFAULT '',
      meta JSONB DEFAULT '{}'::jsonb,
      created_at BIGINT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS rounds (
      id BIGSERIAL PRIMARY KEY,
      round_number BIGINT NOT NULL,
      round_code TEXT DEFAULT '',
      starts_at BIGINT NOT NULL,
      betting_closes_at BIGINT NOT NULL,
      ends_at BIGINT NOT NULL,
      status TEXT NOT NULL,
      server_seed TEXT NOT NULL,
      server_seed_hash TEXT NOT NULL,
      client_seed TEXT NOT NULL,
      lucky_number INTEGER,
      settled_at BIGINT,
      created_at BIGINT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS bets (
      id BIGSERIAL PRIMARY KEY,
      round_id BIGINT NOT NULL,
      user_id BIGINT NOT NULL,
      bet_map JSONB NOT NULL,
      total_coins NUMERIC NOT NULL,
      matched_number INTEGER,
      payout NUMERIC DEFAULT 0,
      result TEXT DEFAULT 'pending',
      created_at BIGINT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS deposit_requests (
      id BIGSERIAL PRIMARY KEY,
      user_id BIGINT NOT NULL,
      username TEXT NOT NULL,
      amount NUMERIC NOT NULL,
      method TEXT DEFAULT '',
      utr TEXT DEFAULT '',
      screenshot TEXT DEFAULT '',
      status TEXT DEFAULT 'pending',
      archived BOOLEAN DEFAULT FALSE,
      created_at BIGINT NOT NULL,
      updated_at BIGINT
    );

    CREATE TABLE IF NOT EXISTS withdraw_requests (
      id BIGSERIAL PRIMARY KEY,
      user_id BIGINT NOT NULL,
      username TEXT NOT NULL,
      amount NUMERIC NOT NULL,
      method TEXT DEFAULT '',
      upi_id TEXT DEFAULT '',
      details JSONB DEFAULT '{}'::jsonb,
      status TEXT DEFAULT 'pending',
      archived BOOLEAN DEFAULT FALSE,
      created_at BIGINT NOT NULL,
      updated_at BIGINT
    );

    CREATE TABLE IF NOT EXISTS transactions (
      id BIGSERIAL PRIMARY KEY,
      user_id BIGINT NOT NULL,
      type TEXT NOT NULL,
      amount NUMERIC NOT NULL,
      meta JSONB DEFAULT '{}'::jsonb,
      created_at BIGINT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS live_updates (
      id BIGSERIAL PRIMARY KEY,
      payment_method JSONB DEFAULT '{}'::jsonb,
      offer TEXT DEFAULT ''
    );

    CREATE TABLE IF NOT EXISTS global_chat_messages (
      id BIGSERIAL PRIMARY KEY,
      user_id BIGINT NOT NULL,
      username TEXT NOT NULL,
      message TEXT NOT NULL,
      reactions JSONB DEFAULT '{}'::jsonb,
      is_hidden BOOLEAN DEFAULT FALSE,
      created_at BIGINT NOT NULL
    );
  `);

  await pool.query(`
    ALTER TABLE rounds ADD COLUMN IF NOT EXISTS round_code TEXT DEFAULT '';
    ALTER TABLE withdraw_requests ADD COLUMN IF NOT EXISTS upi_id TEXT DEFAULT '';
    ALTER TABLE users ADD COLUMN IF NOT EXISTS admin_role TEXT DEFAULT 'read_only';
    ALTER TABLE users ADD COLUMN IF NOT EXISTS last_active_at BIGINT DEFAULT 0;
  `);

  await ensureWalletColumnsReady();
  await ensureDeviceColumnsReady();

  await pool.query(`
    CREATE INDEX IF NOT EXISTS idx_users_session_token ON users(session_token);
    CREATE INDEX IF NOT EXISTS idx_rounds_round_number ON rounds(round_number DESC);
    CREATE INDEX IF NOT EXISTS idx_rounds_status ON rounds(status);
    CREATE INDEX IF NOT EXISTS idx_bets_user_round ON bets(user_id, round_id);
    CREATE INDEX IF NOT EXISTS idx_bets_round_id ON bets(round_id);
    CREATE INDEX IF NOT EXISTS idx_transactions_user_created_at ON transactions(user_id, created_at DESC);
    CREATE INDEX IF NOT EXISTS idx_transactions_type ON transactions(type);
    CREATE INDEX IF NOT EXISTS idx_deposit_requests_user_created_at ON deposit_requests(user_id, created_at DESC);
    CREATE INDEX IF NOT EXISTS idx_withdraw_requests_user_created_at ON withdraw_requests(user_id, created_at DESC);
    CREATE INDEX IF NOT EXISTS idx_global_chat_messages_created_at ON global_chat_messages(created_at DESC);
  `);

  console.log('DB Tables Ready');
}

async function ensureUsersSeeded() {
  const seedUsers = [
    {
      id: 999,
      username: 'admin',
      password: `sha256$${hashPassword('pk0079@sk')}`,
      session_token: '',
      wallet_balance: 0,
      bonus_balance: 0,
      deposit_balance: 0,
      winning_balance: 0,
      total_played: 0,
      total_wins: 0,
      bonus_claimed: 0,
      last_bonus_time: 0,
      blocked: false,
      is_admin: true,
      created_at: nowMs()
    },
    {
      id: DEMO_USER_ID,
      username: 'demo-user',
      password: '',
      session_token: '',
      wallet_balance: 1000,
      bonus_balance: 0,
      deposit_balance: 1000,
      winning_balance: 0,
      total_played: 0,
      total_wins: 0,
      bonus_claimed: 0,
      last_bonus_time: 0,
      blocked: false,
      is_admin: false,
      created_at: nowMs()
    }
  ];

  for (const user of seedUsers) {
    await pool.query(
  `INSERT INTO users (
    id, username, password, session_token, wallet_balance, bonus_balance, deposit_balance, winning_balance, total_played, total_wins,
    bonus_claimed, last_bonus_time, blocked, is_admin, admin_role, last_active_at, created_at
  )
  VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17)
  ON CONFLICT (username) DO UPDATE SET
    password = CASE
      WHEN EXCLUDED.username = 'admin' THEN EXCLUDED.password
      ELSE users.password
    END,
    is_admin = CASE
      WHEN EXCLUDED.username = 'admin' THEN TRUE
      ELSE users.is_admin
    END,
    admin_role = CASE
      WHEN EXCLUDED.username = 'admin' THEN 'super_admin'
      ELSE users.admin_role
    END,
    blocked = CASE
      WHEN EXCLUDED.username = 'admin' THEN FALSE
      ELSE users.blocked
    END`,
  [
    user.id,
    user.username,
    user.password,
    user.session_token,
    Number(user.wallet_balance || 0),
    Number(user.bonus_balance || 0),
    Number(user.deposit_balance || 0),
    Number(user.winning_balance || 0),
    Number(user.total_played || 0),
    Number(user.total_wins || 0),
    Number(user.bonus_claimed || 0),
    Number(user.last_bonus_time || 0),
    Boolean(user.blocked),
    Boolean(user.is_admin),
    Boolean(user.is_admin) ? 'super_admin' : 'read_only',
    0,
    Number(user.created_at || nowMs())
  ]
);
  }
}

async function ensureLiveUpdatesSeeded() {
  const result = await pool.query(`SELECT id FROM live_updates LIMIT 1`);
  if (!result.rows.length) {
    await pool.query(
      `INSERT INTO live_updates (payment_method, offer) VALUES ($1, $2)`,
      [JSON.stringify({ upiId: '', qrCodeImage: '', bankAccount: '' }), '']
    );
  }
}

async function getLiveUpdatesRow() {
  const result = await pool.query(`SELECT * FROM live_updates ORDER BY id ASC LIMIT 1`);
  if (result.rows.length) return result.rows[0];

  const inserted = await pool.query(
    `INSERT INTO live_updates (payment_method, offer)
     VALUES ($1, $2)
     RETURNING *`,
    [JSON.stringify({ upiId: '', qrCodeImage: '', bankAccount: '' }), '']
  );

  return inserted.rows[0];
}


async function getUser(userId) {
  const result = await pool.query(`SELECT * FROM users WHERE id = $1 LIMIT 1`, [userId]);
  return normalizeWalletUser(result.rows[0] || null);
}

async function getUserByUsername(username) {
  const result = await pool.query(
    `SELECT * FROM users WHERE LOWER(username) = LOWER($1) LIMIT 1`,
    [String(username || '').trim()]
  );
  return normalizeWalletUser(result.rows[0] || null);
}

async function getUserBySessionToken(token) {
  const result = await pool.query(`SELECT * FROM users WHERE session_token = $1 LIMIT 1`, [String(token || '').trim()]);
  return normalizeWalletUser(result.rows[0] || null);
}

async function updateUserSessionToken(userId, sessionToken) {
  await pool.query(`UPDATE users SET session_token = $1 WHERE id = $2`, [sessionToken, userId]);
}

async function createUserRecord({ username, password, walletBalance = JOINING_BONUS_AMOUNT, isAdmin = false, bonusBalance = null, depositBalance = null, winningBalance = null, deviceFingerprint = '', signupBonusGiven = false }) {
  const createdAt = nowMs();
  const resolvedBonusBalance = Number(bonusBalance !== null ? bonusBalance : (isAdmin ? 0 : JOINING_BONUS_AMOUNT));
  const resolvedDepositBalance = Number(depositBalance !== null ? depositBalance : 0);
  const resolvedWinningBalance = Number(winningBalance !== null ? winningBalance : 0);
  const resolvedWalletBalance = Number(
    walletBalance !== undefined && walletBalance !== null
      ? walletBalance
      : (resolvedBonusBalance + resolvedDepositBalance + resolvedWinningBalance)
  );

  const result = await pool.query(
    `INSERT INTO users (
      username, password, session_token, wallet_balance, bonus_balance, deposit_balance, winning_balance, total_played, total_wins,
      bonus_claimed, last_bonus_time, blocked, is_admin, admin_role, last_active_at, created_at, device_fingerprint, signup_bonus_given
    )
    VALUES ($1,$2,$3,$4,$5,$6,$7,0,0,0,0,false,$8,$9,0,$10,$11,$12)
    RETURNING *`,
    [username, password, crypto.randomUUID(), resolvedWalletBalance, resolvedBonusBalance, resolvedDepositBalance, resolvedWinningBalance, isAdmin, isAdmin ? 'super_admin' : 'read_only', createdAt, sanitizeDeviceFingerprint(deviceFingerprint), Boolean(signupBonusGiven)]
  );
  return normalizeWalletUser(result.rows[0]);
}

async function updateUserFields(userId, fields = {}) {
  const updates = [];
  const values = [];
  let index = 1;
  for (const [key, value] of Object.entries(fields)) {
    updates.push(`${key} = $${index++}`);
    values.push(value);
  }
  if (!updates.length) return;
  values.push(userId);
  await pool.query(`UPDATE users SET ${updates.join(', ')} WHERE id = $${index}`, values);
}

async function incrementUserFields(userId, increments = {}) {
  const updates = [];
  const values = [];
  let index = 1;
  for (const [key, value] of Object.entries(increments)) {
    updates.push(`${key} = COALESCE(${key}, 0) + $${index++}`);
    values.push(value);
  }
  if (!updates.length) return;
  values.push(userId);
  await pool.query(`UPDATE users SET ${updates.join(', ')} WHERE id = $${index}`, values);
}

async function setUserBlockedStatus(userId, blocked) {
  await pool.query(`UPDATE users SET blocked = $1 WHERE id = $2`, [Boolean(blocked), userId]);
}

async function deleteUserById(userId) {
  await pool.query(`DELETE FROM users WHERE id = $1`, [userId]);
}

async function getUserIdFromReq(req) {
  const token = String(req.header('x-auth-token') || '').trim();
  if (!token) return null;
  const user = await getUserBySessionToken(token);
  return user ? Number(user.id) : null;
}

async function adminOnly(req, res, next) {
  try {
    const userId = await getUserIdFromReq(req);
    if (!userId) return res.status(401).json({ error: 'Login required' });
    const user = await getUser(userId);
    if (!user) return res.status(401).json({ error: 'User not found' });
    if (user.is_admin !== true) return res.status(403).json({ error: 'Admin access only' });
    await updateUserFields(user.id, { last_active_at: nowMs() });
    user.admin_role = user.admin_role || 'super_admin';
    req.user = user;
    next();
  } catch (error) {
    console.error('ADMIN AUTH ERROR:', error);
    return res.status(500).json({ error: 'Admin auth failed' });
  }
}


function normalizeAdminRole(role, isAdmin = false) {
  const allowed = new Set(['super_admin', 'finance_admin', 'game_admin', 'support_admin', 'read_only']);
  const safeRole = String(role || '').trim().toLowerCase();
  if (allowed.has(safeRole)) return safeRole;
  return isAdmin ? 'super_admin' : 'read_only';
}

function requireAdminRoles(...roles) {
  const allowed = new Set(roles.flat().map(role => normalizeAdminRole(role)));
  return (req, res, next) => {
    const role = normalizeAdminRole(req.user?.admin_role, req.user?.is_admin === true);
    req.user.admin_role = role;
    if (!allowed.has(role)) {
      return res.status(403).json({ error: 'Access denied for your role' });
    }
    next();
  };
}

function sanitizeAdminUsername(value) {
  return String(value || '').trim();
}

function sanitizeAdminPassword(value) {
  return String(value || '').trim();
}

function toJson(value, fallback = {}) {
  if (value === null || value === undefined) return fallback;
  if (typeof value === 'object') return value;
  return jsonParseSafe(value, fallback);
}

function parseDateOnlyToStartMs(value) {
  const safe = String(value || '').trim();
  if (!/^\d{4}-\d{2}-\d{2}$/.test(safe)) return null;
  const dt = new Date(`${safe}T00:00:00.000Z`);
  const ms = dt.getTime();
  return Number.isFinite(ms) ? ms : null;
}

function parseDateOnlyToEndMs(value) {
  const start = parseDateOnlyToStartMs(value);
  if (start === null) return null;
  return start + (24 * 60 * 60 * 1000) - 1;
}

function getAdminRangeFromQuery(query = {}) {
  const preset = String(query.preset || '').trim().toLowerCase();
  const now = nowMs();
  const startTodayDate = new Date(now);
  startTodayDate.setHours(0, 0, 0, 0);
  const startToday = startTodayDate.getTime();
  const startYesterday = startToday - 24 * 60 * 60 * 1000;
  let from = null;
  let to = null;
  if (preset === 'today') { from = startToday; to = now; }
  else if (preset === 'yesterday') { from = startYesterday; to = startToday - 1; }
  else if (preset === 'last45days') { from = startToday - (44 * 24 * 60 * 60 * 1000); to = now; }
  const fromInput = parseDateOnlyToStartMs(query.from);
  const toInput = parseDateOnlyToEndMs(query.to);
  if (fromInput !== null && toInput !== null) { from = fromInput; to = toInput; }
  if (from === null || to === null) { from = startToday; to = now; }
  if (to < from) { const temp = from; from = to; to = temp; }
  const maxWindowMs = 45 * 24 * 60 * 60 * 1000;
  if ((to - from) > maxWindowMs) from = to - maxWindowMs;
  const previousWindow = Math.max(24 * 60 * 60 * 1000, (to - from) + 1);
  return { preset: preset || 'today', from, to, previousFrom: from - previousWindow, previousTo: from - 1 };
}

function csvEscape(value) {
  const safe = String(value ?? '');
  return `"${safe.replace(/"/g, '""')}"`;
}

function toCsv(rows = []) {
  if (!Array.isArray(rows) || !rows.length) return '';
  const headers = Object.keys(rows[0]);
  const lines = [headers.map(csvEscape).join(',')];
  for (const row of rows) lines.push(headers.map(key => csvEscape(row[key])).join(','));
  return lines.join('\n');
}

function sendCsv(res, filename, rows) {
  res.setHeader('Content-Type', 'text/csv; charset=utf-8');
  res.setHeader('Content-Disposition', `attachment; filename="${filename}"`);
  return res.status(200).send(toCsv(rows));
}


function getRandomDailyBonusAmount() {
  return Math.floor(Math.random() * (DAILY_BONUS_MAX - DAILY_BONUS_MIN + 1)) + DAILY_BONUS_MIN;
}

function normalizeWalletUser(user) {
  if (!user) return null;
  const normalized = { ...user };
  normalized.bonus_balance = Number(normalized.bonus_balance || 0);
  normalized.deposit_balance = Number(normalized.deposit_balance || 0);
  normalized.winning_balance = Number(normalized.winning_balance || 0);
  normalized.wallet_balance = Number(normalized.wallet_balance || 0);
  normalized.total_played = Number(normalized.total_played || 0);

  const derivedMainBalance = normalized.bonus_balance + normalized.deposit_balance + normalized.winning_balance;

  if (Math.abs(derivedMainBalance - normalized.wallet_balance) > 0.0001) {
    normalized.wallet_balance = derivedMainBalance;
  }

  return normalized;
}

function calculateMainBalance(user) {
  const normalized = normalizeWalletUser(user);
  return Number(
    (normalized?.bonus_balance || 0) +
    (normalized?.deposit_balance || 0) +
    (normalized?.winning_balance || 0)
  );
}

function calculateEligibleRequestBalance(user) {
  const normalized = normalizeWalletUser(user);
  return Number((normalized?.deposit_balance || 0) + (normalized?.winning_balance || 0));
}

async function refreshMainBalance(userId) {
  const user = normalizeWalletUser(await getUser(userId));
  if (!user) return null;
  const walletBalance = calculateMainBalance(user);
  if (Math.abs(Number(user.wallet_balance || 0) - walletBalance) > 0.0001) {
    await updateUserFields(userId, { wallet_balance: walletBalance });
    user.wallet_balance = walletBalance;
  }
  return user;
}

async function ensureWalletColumnsReady() {
  await pool.query(`
    ALTER TABLE users ADD COLUMN IF NOT EXISTS bonus_balance NUMERIC DEFAULT 0;
    ALTER TABLE users ADD COLUMN IF NOT EXISTS deposit_balance NUMERIC DEFAULT 0;
    ALTER TABLE users ADD COLUMN IF NOT EXISTS winning_balance NUMERIC DEFAULT 0;
  `);

  await pool.query(`
    UPDATE users
    SET
      bonus_balance = COALESCE(bonus_balance, 0),
      deposit_balance = CASE
        WHEN COALESCE(deposit_balance, 0) = 0 AND COALESCE(winning_balance, 0) = 0 AND COALESCE(wallet_balance, 0) > 0
          THEN COALESCE(wallet_balance, 0)
        ELSE COALESCE(deposit_balance, 0)
      END,
      winning_balance = COALESCE(winning_balance, 0)
  `);

  await pool.query(`
    UPDATE users
    SET wallet_balance = COALESCE(bonus_balance, 0) + COALESCE(deposit_balance, 0) + COALESCE(winning_balance, 0)
  `);
}

function getWalletBreakdown(user) {
  const normalized = normalizeWalletUser(user);
  const mainBalance = calculateMainBalance(normalized);
  const eligibleRequestBalance = calculateEligibleRequestBalance(normalized);
  const totalPlayedCoins = Number(normalized?.total_played || 0);

  return {
    mainBalance,
    bonusBalance: Number(normalized?.bonus_balance || 0),
    depositBalance: Number(normalized?.deposit_balance || 0),
    winningBalance: Number(normalized?.winning_balance || 0),
    eligibleRequestBalance,
    totalPlayedCoins,
    playRequirementTarget: MIN_PLAY_BEFORE_REQUEST,
    playRequirementRemaining: Math.max(0, MIN_PLAY_BEFORE_REQUEST - totalPlayedCoins),
    canRequest: totalPlayedCoins >= MIN_PLAY_BEFORE_REQUEST && eligibleRequestBalance >= MIN_REQUEST_AMOUNT
  };
}

function splitRequestDeduction(user, amount) {
  const normalized = normalizeWalletUser(user);
  const totalEligible = calculateEligibleRequestBalance(normalized);

  if (amount > totalEligible) {
    return { success: false, message: 'Eligible request balance is too low' };
  }

  const depositUsed = Math.min(Number(normalized.deposit_balance || 0), amount);
  const winningUsed = Math.max(0, amount - depositUsed);

  return {
    success: true,
    depositUsed,
    winningUsed
  };
}

function computeBetWalletUsage(user, betAmount) {
  const normalized = normalizeWalletUser(user);
  const totalAvailable = calculateMainBalance(normalized);

  if (betAmount > totalAvailable) {
    return { success: false, message: 'Insufficient coins' };
  }

  let remaining = Number(betAmount || 0);
  let bonusUsed = 0;
  let depositUsed = 0;
  let winningUsed = 0;

  const halfForBonus = Math.floor(betAmount / 2);
  const halfForDeposit = betAmount - halfForBonus;

  bonusUsed = Math.min(normalized.bonus_balance, halfForBonus);
  depositUsed = Math.min(normalized.deposit_balance, halfForDeposit);
  remaining -= bonusUsed + depositUsed;

  const bonusLeft = normalized.bonus_balance - bonusUsed;
  if (remaining > 0 && bonusLeft > 0) {
    const extraBonus = Math.min(bonusLeft, remaining);
    bonusUsed += extraBonus;
    remaining -= extraBonus;
  }

  const depositLeft = normalized.deposit_balance - depositUsed;
  if (remaining > 0 && depositLeft > 0) {
    const extraDeposit = Math.min(depositLeft, remaining);
    depositUsed += extraDeposit;
    remaining -= extraDeposit;
  }

  if (remaining > 0) {
    winningUsed = Math.min(normalized.winning_balance, remaining);
    remaining -= winningUsed;
  }

  if (remaining > 0) {
    return { success: false, message: 'Insufficient coins' };
  }

  return {
    success: true,
    bonusUsed,
    depositUsed,
    winningUsed
  };
}

function buildRoundCode(roundNumber, startsAt) {
  const dateObj = new Date(startsAt);
  const year = String(dateObj.getFullYear());
  const month = String(dateObj.getMonth() + 1).padStart(2, '0');
  const day = String(dateObj.getDate()).padStart(2, '0');
  const displayRoundNumber = ((roundNumber - 1) % 50000) + 1;
  return `${year}${month}${day}${String(displayRoundNumber).padStart(5, '0')}`;
}

async function getCurrentRound() {
  const result = await pool.query(
    `SELECT * FROM rounds
     WHERE status IN ('open','closed')
     ORDER BY round_number DESC
     LIMIT 1`
  );
  return result.rows[0] || null;
}

async function getLastSettledRound() {
  const result = await pool.query(
    `SELECT * FROM rounds
     WHERE status = 'settled'
     ORDER BY round_number DESC
     LIMIT 1`
  );
  return result.rows[0] || null;
}

async function getLast10SettledRounds() {
  const result = await pool.query(
    `SELECT round_number, lucky_number
     FROM rounds
     WHERE status = 'settled' AND lucky_number IS NOT NULL
     ORDER BY round_number DESC
     LIMIT 10`
  );
  return result.rows.map(row => ({
    roundNumber: Number(row.round_number),
    luckyNumber: Number(row.lucky_number)
  }));
}

async function getBetForRound(userId, roundId) {
  const result = await pool.query(
    `SELECT * FROM bets WHERE user_id = $1 AND round_id = $2 LIMIT 1`,
    [userId, roundId]
  );
  const row = result.rows[0] || null;
  if (!row) return null;
  row.bet_map = toJson(row.bet_map, {});
  return row;
}

async function getRecentHistory(userId = null, limit = 500) {
  const roundsResult = await pool.query(
    `SELECT * FROM rounds
     WHERE status = 'settled'
     ORDER BY round_number DESC
     LIMIT $1`,
    [limit]
  );
  const settledRounds = roundsResult.rows;

  let betMapByRound = new Map();
  if (userId) {
    const betsResult = await pool.query(
      `SELECT * FROM bets WHERE user_id = $1`,
      [userId]
    );
    for (const row of betsResult.rows) {
      row.bet_map = toJson(row.bet_map, {});
      betMapByRound.set(Number(row.round_id), row);
    }
  }

  return settledRounds.map(round => {
    const userBet = userId ? betMapByRound.get(Number(round.id)) : null;
    const betSummary = userBet
      ? Object.entries(userBet.bet_map || {}).map(([num, amt]) => `${num}:${amt}`).join(', ')
      : '-';

    return {
      round_number: Number(round.round_number),
      round_code: round.round_code || buildRoundCode(Number(round.round_number || 1), Number(round.starts_at)),
      lucky_number: round.lucky_number === null ? null : Number(round.lucky_number),
      bet_map: userBet ? userBet.bet_map : {},
      bet_display: betSummary || '-',
      result: userBet ? userBet.result || '-' : '-',
      payout: userBet && Number(userBet.payout) !== 0 ? Number(userBet.payout) : '-',
      isWinner: userBet ? userBet.result === 'win' : false,
      total_coins: userBet ? Number(userBet.total_coins || 0) : 0,
      hasBet: Boolean(userBet)
    };
  });
}

async function createRound(roundNumber, startsAt) {
  const bettingClosesAt = startsAt + (ROUND_SECONDS - BETTING_CLOSE_SECONDS) * 1000;
  const endsAt = startsAt + ROUND_SECONDS * 1000;
  const serverSeed = randomHex(32);
  const clientSeed = `round-${roundNumber}-public-demo-seed`;
  const serverSeedHash = sha256(serverSeed);
  const roundCode = buildRoundCode(roundNumber, startsAt);

  const result = await pool.query(
    `INSERT INTO rounds (
      round_number, round_code, starts_at, betting_closes_at, ends_at, status,
      server_seed, server_seed_hash, client_seed, lucky_number, settled_at, created_at
    )
    VALUES ($1,$2,$3,$4,$5,'open',$6,$7,$8,NULL,NULL,$9)
    RETURNING *`,
    [roundNumber, roundCode, startsAt, bettingClosesAt, endsAt, serverSeed, serverSeedHash, clientSeed, nowMs()]
  );

  return result.rows[0];
}

function computeLuckyNumber(serverSeed, clientSeed, roundNumber) {
  const digest = sha256(`${serverSeed}:${clientSeed}:${roundNumber}`);
  const value = parseInt(digest.slice(0, 8), 16);
  return value % 10;
}

function getStatusForRound(round) {
  const now = nowMs();
  if (!round) return 'waiting';
  if (now < Number(round.betting_closes_at)) return 'open';
  if (now < Number(round.ends_at)) return 'closed';
  return 'awaiting_settlement';
}

async function addTransaction(userId, type, amount, meta = {}) {
  await pool.query(
    `INSERT INTO transactions (user_id, type, amount, meta, created_at)
     VALUES ($1,$2,$3,$4,$5)`,
    [userId, type, amount, JSON.stringify(meta || {}), nowMs()]
  );
}

async function settleRoundTx(roundId) {
  const roundResult = await pool.query(`SELECT * FROM rounds WHERE id = $1 LIMIT 1`, [roundId]);
  const round = roundResult.rows[0] || null;
  if (!round) throw new Error('Round not found');

  if (round.status === 'settled') {
    return round;
  }

  if (nowMs() < Number(round.ends_at)) {
    throw new Error('Round timer not finished yet');
  }

  const luckyNumber = computeLuckyNumber(round.server_seed, round.client_seed, Number(round.round_number));

  await pool.query(
    `UPDATE rounds
     SET status = 'settled', lucky_number = $1, settled_at = $2
     WHERE id = $3`,
    [luckyNumber, nowMs(), round.id]
  );

  const betsResult = await pool.query(`SELECT * FROM bets WHERE round_id = $1`, [round.id]);
  for (const bet of betsResult.rows) {
    const betMap = toJson(bet.bet_map, {});
    const matchedAmount = Number(betMap[String(luckyNumber)] || 0);
    const payout = matchedAmount > 0 ? matchedAmount * PAYOUT_MULTIPLIER : 0;
    const result = payout > 0 ? 'win' : 'lose';

    await pool.query(
      `UPDATE bets
       SET matched_number = $1, payout = $2, result = $3
       WHERE id = $4`,
      [luckyNumber, payout, result, bet.id]
    );

    if (payout > 0) {
      await incrementUserFields(Number(bet.user_id), {
        wallet_balance: payout,
        winning_balance: payout,
        total_wins: 1
      });

      await addTransaction(Number(bet.user_id), 'win_credit', payout, {
        roundId: Number(round.id),
        luckyNumber,
        walletType: 'winning'
      });
    }
  }
}

async function ensureActiveRound() {
  const result = await pool.query(`SELECT * FROM rounds ORDER BY round_number DESC LIMIT 1`);
  const latest = result.rows[0] || null;
  const now = nowMs();

  if (!latest) {
    return await createRound(1, now);
  }

  if (latest.status !== 'settled') {
    if (latest.status === 'open' && now >= Number(latest.betting_closes_at)) {
      await pool.query(`UPDATE rounds SET status = 'closed' WHERE id = $1`, [latest.id]);
      latest.status = 'closed';
    }

    if (now >= Number(latest.ends_at)) {
      await settleRoundTx(latest.id);
      return await createRound(Number(latest.round_number) + 1, nowMs());
    }

    return latest;
  }

  return await createRound(Number(latest.round_number) + 1, now);
}

async function createNextRoundIfNeeded() {
  return await ensureActiveRound();
}

async function syncRoundState() {
  return await ensureActiveRound();
}

async function buildGameState(userId = DEMO_USER_ID) {
  const round = await syncRoundState();
  const user = userId ? await refreshMainBalance(userId) : null;

  if (!user) {
    return {
      user: {
        id: null,
        username: 'Guest',
        walletBalance: 0,
        mainBalance: 0,
        bonusBalance: 0,
        depositBalance: 0,
        winningBalance: 0,
        eligibleRequestBalance: 0,
        totalPlayed: 0,
        totalPlayedCoins: 0,
        playRequirementTarget: MIN_PLAY_BEFORE_REQUEST,
        playRequirementRemaining: MIN_PLAY_BEFORE_REQUEST,
        totalWins: 0,
        bonusClaimed: 0,
        lastBonusTime: null
      },
      round: round ? {
        id: Number(round.id),
        roundNumber: Number(round.round_number),
        startsAt: Number(round.starts_at),
        bettingClosesAt: Number(round.betting_closes_at),
        endsAt: Number(round.ends_at),
        status: getStatusForRound(round),
        serverSeedHash: round.server_seed_hash,
        clientSeed: round.client_seed,
        alreadyPlaced: false
      } : null,
      placedBet: null,
      lastSettledRound: null,
      last10LuckyNumbers: await getLast10SettledRounds(),
      history: []
    };
  }

  const placedBet = round ? await getBetForRound(Number(user.id), Number(round.id)) : null;
  const lastSettled = await getLastSettledRound();
  const history = await getRecentHistory(Number(user.id));

  const depositResult = await pool.query(`SELECT * FROM deposit_requests WHERE user_id = $1 ORDER BY created_at DESC`, [user.id]);
  const withdrawResult = await pool.query(`SELECT * FROM withdraw_requests WHERE user_id = $1 ORDER BY created_at DESC`, [user.id]);

  return {
    user: {
      id: Number(user.id),
      username: user.username,
      walletBalance: Number(user.wallet_balance || 0),
      ...getWalletBreakdown(user),
      totalPlayed: Number(user.total_played || 0),
      totalPlayedCoins: Number(user.total_played || 0),
      totalWins: Number(user.total_wins || 0),
      bonusClaimed: Number(user.bonus_claimed || 0),
      lastBonusTime: Number(user.last_bonus_time || 0)
    },
    round: round ? {
      id: Number(round.id),
      roundNumber: Number(round.round_number),
      startsAt: Number(round.starts_at),
      bettingClosesAt: Number(round.betting_closes_at),
      endsAt: Number(round.ends_at),
      status: getStatusForRound(round),
      serverSeedHash: round.server_seed_hash,
      clientSeed: round.client_seed,
      alreadyPlaced: Boolean(placedBet)
    } : null,
    placedBet: placedBet ? {
      totalCoins: Number(placedBet.total_coins || 0),
      betMap: toJson(placedBet.bet_map, {}),
      result: placedBet.result,
      payout: Number(placedBet.payout || 0)
    } : null,
    lastSettledRound: lastSettled ? {
      roundNumber: Number(lastSettled.round_number),
      luckyNumber: Number(lastSettled.lucky_number),
      serverSeedHash: lastSettled.server_seed_hash,
      serverSeed: lastSettled.server_seed,
      clientSeed: lastSettled.client_seed,
      settledAt: Number(lastSettled.settled_at || 0)
    } : null,
    last10LuckyNumbers: await getLast10SettledRounds(),
    history,
    depositRequests: depositResult.rows,
    withdrawRequests: withdrawResult.rows
  };
}

function validateBetMap(betMap) {
  if (!betMap || typeof betMap !== 'object' || Array.isArray(betMap)) {
    return { ok: false, error: 'Invalid bet map' };
  }
  const keys = Object.keys(betMap);
  if (keys.length === 0) return { ok: false, error: 'Select at least one number' };
  if (keys.length > 10) return { ok: false, error: 'Too many selections' };

  let total = 0;
  const sanitized = {};
  for (const key of keys) {
    if (!/^\d$/.test(key)) return { ok: false, error: 'Only numbers 0 to 9 are allowed' };
    const amount = Number(betMap[key]);
    if (!Number.isInteger(amount) || amount <= 0) return { ok: false, error: 'Each bet amount must be a positive integer' };
    if (amount > 10000) return { ok: false, error: 'Single number amount limit is 10000' };
    total += amount;
    sanitized[key] = amount;
  }
  if (total < 1) return { ok: false, error: 'Minimum total bet is 1 coin' };
  if (total > 50000) return { ok: false, error: 'Maximum total bet is 50000 coins' };
  return { ok: true, sanitized, total };
}

async function placeBetTx(userId, roundId, betMap, totalCoins) {
  const user = await refreshMainBalance(userId);
  if (!user) throw new Error('User not found');

  const usage = computeBetWalletUsage(user, totalCoins);
  if (!usage.success) throw new Error(usage.message || 'Insufficient coins');

  const existingBet = await getBetForRound(userId, roundId);
  if (existingBet) throw new Error('Bet already placed for this round');

  await pool.query(
    `INSERT INTO bets (round_id, user_id, bet_map, total_coins, matched_number, payout, result, created_at)
     VALUES ($1,$2,$3,$4,NULL,0,'pending',$5)`,
    [roundId, userId, JSON.stringify(betMap), totalCoins, nowMs()]
  );

  await incrementUserFields(userId, {
    wallet_balance: -totalCoins,
    bonus_balance: -Number(usage.bonusUsed || 0),
    deposit_balance: -Number(usage.depositUsed || 0),
    winning_balance: -Number(usage.winningUsed || 0),
    total_played: totalCoins
  });

  await addTransaction(userId, 'bet_debit', -totalCoins, {
    roundId,
    bonusUsed: Number(usage.bonusUsed || 0),
    depositUsed: Number(usage.depositUsed || 0),
    winningUsed: Number(usage.winningUsed || 0)
  });
}

async function claimBonusTx(userId) {
  const user = await getUser(userId);
  if (!user) throw new Error('User not found');
  const current = nowMs();
  if (current - Number(user.last_bonus_time || 0) < BONUS_COOLDOWN_MS) {
    throw new Error('Bonus is not available yet');
  }

  const bonusAmount = getRandomDailyBonusAmount();

  await incrementUserFields(userId, {
    wallet_balance: bonusAmount,
    bonus_balance: bonusAmount,
    bonus_claimed: 1
  });

  await updateUserFields(userId, { last_bonus_time: current });
  await addTransaction(userId, 'bonus_credit', bonusAmount, { walletType: 'bonus' });

  return bonusAmount;
}


async function logAdminActivity(adminUser, action, targetUser = null, meta = {}) {
  try {
    await pool.query(
      `INSERT INTO admin_activity_logs (
        admin_user_id, admin_username, action, target_user_id, target_username, meta, created_at
      ) VALUES ($1,$2,$3,$4,$5,$6,$7)`,
      [
        Number(adminUser?.id || 0),
        String(adminUser?.username || 'admin'),
        String(action || ''),
        targetUser ? Number(targetUser.id || 0) : null,
        targetUser ? String(targetUser.username || '') : '',
        JSON.stringify(meta || {}),
        nowMs()
      ]
    );
  } catch (error) {
    console.error('ADMIN ACTIVITY LOG ERROR:', error);
  }
}

app.post('/api/login', async (req, res) => {
  try {
    const username = String(req.body?.username || '').trim();
    const password = String(req.body?.password || '').trim();

    if (!username) return res.status(400).json({ error: 'Username required' });
    if (!password) return res.status(400).json({ error: 'Password required' });

    const user = await getUserByUsername(username);
    if (!user) return res.status(404).json({ error: 'Username does not exist. Please sign up first.' });
    if (!isPasswordMatch(user, password)) return res.status(401).json({ error: 'Wrong password' });
    if (user.blocked) return res.status(403).json({ error: 'Your account is blocked by admin' });

    const newSessionToken = crypto.randomUUID();
    await updateUserSessionToken(user.id, newSessionToken);

    return res.json({
      success: true,
      user: {
        id: Number(user.id),
        username: user.username,
        sessionToken: newSessionToken,
        walletBalance: Number(user.wallet_balance || 0),
        mainBalance: Number(user.wallet_balance || 0),
        bonusBalance: Number(user.bonus_balance || 0),
        depositBalance: Number(user.deposit_balance || 0),
        winningBalance: Number(user.winning_balance || 0),
        eligibleRequestBalance: calculateEligibleRequestBalance(user),
        totalPlayed: Number(user.total_played || 0),
        totalWins: Number(user.total_wins || 0),
        bonusClaimed: Number(user.bonus_claimed || 0),
        lastBonusTime: Number(user.last_bonus_time || 0),
        role: user.admin_role || (user.is_admin ? 'super_admin' : 'read_only')
      }
    });
  } catch (error) {
    console.error('LOGIN ERROR:', error);
    return res.status(500).json({ error: 'Login failed' });
  }
});

app.post('/api/admin-login', adminLoginLimiter, async (req, res) => {
  try {
    const adminKey = String(req.header('x-admin-key') || '').trim();
    const username = String(req.body?.username || '').trim();
    const password = String(req.body?.password || '').trim();

    if (!ADMIN_KEY || adminKey !== ADMIN_KEY) return res.status(404).json({ error: 'Not found' });
    if (!username) return res.status(400).json({ error: 'Username required' });
    if (!password) return res.status(400).json({ error: 'Password required' });

    const user = await getUserByUsername(username);
    if (!user || user.is_admin !== true) return res.status(401).json({ error: 'Admin account not found' });

    const role = normalizeAdminRole(user.admin_role, true);
    if (role === 'read_only') return res.status(403).json({ error: 'Read-only admin cannot login from panel' });

    if (user.blocked) return res.status(403).json({ error: 'Your account is blocked by admin' });
    if (!isPasswordMatch(user, password)) return res.status(401).json({ error: 'Invalid admin password' });

    const newSessionToken = crypto.randomUUID();
    await updateUserSessionToken(user.id, newSessionToken);

    return res.json({
      success: true,
      user: {
        id: Number(user.id),
        username: user.username,
        sessionToken: newSessionToken,
        walletBalance: Number(user.wallet_balance || 0),
        mainBalance: Number(user.wallet_balance || 0),
        bonusBalance: Number(user.bonus_balance || 0),
        depositBalance: Number(user.deposit_balance || 0),
        winningBalance: Number(user.winning_balance || 0),
        eligibleRequestBalance: calculateEligibleRequestBalance(user),
        totalPlayed: Number(user.total_played || 0),
        totalWins: Number(user.total_wins || 0),
        bonusClaimed: Number(user.bonus_claimed || 0),
        lastBonusTime: Number(user.last_bonus_time || 0),
        isAdmin: true,
        role: normalizeAdminRole(user.admin_role, true)
      }
    });
  } catch (error) {
    console.error('ADMIN LOGIN ERROR:', error);
    return res.status(500).json({ error: 'Admin login failed' });
  }
});

app.post('/api/signup', async (req, res) => {
  try {
    const username = String(req.body?.username || '').trim();
    const password = String(req.body?.password || '').trim();
    const deviceFingerprint = sanitizeDeviceFingerprint(req.body?.deviceFingerprint || '');

    if (!username) return res.status(400).json({ error: 'Username required' });
    if (!password) return res.status(400).json({ error: 'Password required' });
    if (username.length < 3) return res.status(400).json({ error: 'Username minimum 3 characters' });
    if (password.length < 4) return res.status(400).json({ error: 'Password minimum 4 characters' });
    if (!deviceFingerprint) return res.status(400).json({ error: 'Device verification failed. Refresh and try again.' });

    const existingUser = await getUserByUsername(username);
    if (existingUser) return res.status(409).json({ error: 'Username already exists' });

    const stats = await getDeviceSignupStats(deviceFingerprint);
    if (stats.totalAccounts >= DEVICE_SIGNUP_LIMIT) {
      return res.status(403).json({ error: 'This device has reached the signup limit' });
    }

    const canGiveBonus = stats.bonusAccounts < DEVICE_BONUS_LIMIT;
    const joiningBonus = canGiveBonus ? JOINING_BONUS_AMOUNT : 0;

    const user = await createUserRecord({
      username,
      password: `sha256$${hashPassword(password)}`,
      walletBalance: joiningBonus,
      bonusBalance: joiningBonus,
      depositBalance: 0,
      winningBalance: 0,
      isAdmin: false,
      deviceFingerprint,
      signupBonusGiven: canGiveBonus
    });

    return res.json({
      success: true,
      message: 'Signup successful',
      user: {
        id: Number(user.id),
        username: user.username,
        sessionToken: user.session_token,
        walletBalance: Number(user.wallet_balance || 0),
        mainBalance: Number(user.wallet_balance || 0),
        bonusBalance: Number(user.bonus_balance || 0),
        depositBalance: Number(user.deposit_balance || 0),
        winningBalance: Number(user.winning_balance || 0),
        eligibleRequestBalance: calculateEligibleRequestBalance(user),
        totalPlayed: Number(user.total_played || 0),
        totalWins: Number(user.total_wins || 0),
        bonusClaimed: Number(user.bonus_claimed || 0),
        lastBonusTime: Number(user.last_bonus_time || 0),
        isAdmin: false,
        role: 'user'
      }
    });
  } catch (error) {
    console.error('SIGNUP ERROR:', error);
    return res.status(500).json({ error: 'Signup failed' });
  }
});


app.get('/api/chat', async (req, res) => {
  try {
    const messages = await getRecentChatMessages(CHAT_FETCH_LIMIT, false);
    return res.json({
      success: true,
      reactions: CHAT_REACTIONS,
      messages
    });
  } catch (error) {
    console.error('CHAT LOAD ERROR:', error);
    return res.status(500).json({ error: 'Failed to load chat' });
  }
});

app.post('/api/chat/send', async (req, res) => {
  try {
    const userId = await getUserIdFromReq(req);
    if (!userId) return res.status(401).json({ error: 'Login required' });

    const user = await getUser(userId);
    if (!user) return res.status(404).json({ error: 'User not found' });
    if (user.blocked) return res.status(403).json({ error: 'Blocked users cannot chat' });

    const message = sanitizeChatMessage(req.body?.message || '');
    if (!message) return res.status(400).json({ error: 'Message required' });

    const allowed = await checkChatRateLimit(userId);
    if (!allowed) return res.status(429).json({ error: 'Too many messages. Slow down.' });

    await pool.query(
      `INSERT INTO global_chat_messages (user_id, username, message, reactions, is_hidden, created_at)
       VALUES ($1,$2,$3,$4,FALSE,$5)`,
      [userId, String(user.username || ''), message, JSON.stringify({}), nowMs()]
    );

    return res.json({ success: true, messages: await getRecentChatMessages(CHAT_FETCH_LIMIT, false) });
  } catch (error) {
    console.error('CHAT SEND ERROR:', error);
    return res.status(500).json({ error: 'Failed to send chat message' });
  }
});

app.post('/api/chat/react', async (req, res) => {
  try {
    const userId = await getUserIdFromReq(req);
    if (!userId) return res.status(401).json({ error: 'Login required' });

    const messageId = Number(req.body?.messageId || 0);
    const reaction = sanitizeChatReaction(req.body?.reaction || '');

    if (!Number.isInteger(messageId) || messageId <= 0) return res.status(400).json({ error: 'Valid message required' });
    if (!reaction) return res.status(400).json({ error: 'Valid reaction required' });

    const current = await pool.query(`SELECT reactions FROM global_chat_messages WHERE id = $1 LIMIT 1`, [messageId]);
    if (!current.rows.length) return res.status(404).json({ error: 'Chat message not found' });

    const reactions = toJson(current.rows[0].reactions, {});
    reactions[reaction] = Number(reactions[reaction] || 0) + 1;

    await pool.query(`UPDATE global_chat_messages SET reactions = $1 WHERE id = $2`, [JSON.stringify(reactions), messageId]);
    return res.json({ success: true, messages: await getRecentChatMessages(CHAT_FETCH_LIMIT, false) });
  } catch (error) {
    console.error('CHAT REACTION ERROR:', error);
    return res.status(500).json({ error: 'Failed to update reaction' });
  }
});

app.get('/api/admin/chat', adminOnly, requireAdminRoles('super_admin', 'support_admin', 'read_only'), async (req, res) => {
  try {
    return res.json({ success: true, messages: await getRecentChatMessages(CHAT_FETCH_LIMIT, true), reactions: CHAT_REACTIONS });
  } catch (error) {
    console.error('ADMIN CHAT LOAD ERROR:', error);
    return res.status(500).json({ error: 'Failed to load admin chat' });
  }
});

app.post('/api/admin/chat/hide', adminOnly, requireAdminRoles('super_admin', 'support_admin'), async (req, res) => {
  try {
    const messageId = Number(req.body?.messageId || 0);
    const hidden = Boolean(req.body?.hidden);
    if (!Number.isInteger(messageId) || messageId <= 0) return res.status(400).json({ error: 'Valid message required' });
    await pool.query(`UPDATE global_chat_messages SET is_hidden = $1 WHERE id = $2`, [hidden, messageId]);
    return res.json({ success: true, message: hidden ? 'Chat message hidden' : 'Chat message restored', messages: await getRecentChatMessages(CHAT_FETCH_LIMIT, true) });
  } catch (error) {
    console.error('ADMIN CHAT HIDE ERROR:', error);
    return res.status(500).json({ error: 'Failed to update chat message' });
  }
});

app.post('/api/admin/chat/clear', adminOnly, requireAdminRoles('super_admin'), async (req, res) => {
  try {
    await pool.query(`DELETE FROM global_chat_messages`);
    return res.json({ success: true, message: 'Global chat cleared', messages: [] });
  } catch (error) {
    console.error('ADMIN CHAT CLEAR ERROR:', error);
    return res.status(500).json({ error: 'Failed to clear chat' });
  }
});

app.get('/api/state', async (req, res) => {
  try {
    await createNextRoundIfNeeded();
    const userId = await getUserIdFromReq(req);
    return res.json(await buildGameState(userId));
  } catch (err) {
    console.error('STATE ERROR:', err);
    return res.status(500).json({ error: err.message });
  }
});

app.post('/api/place-bet', async (req, res) => {
  try {
    const userId = await getUserIdFromReq(req);
    if (!userId) return res.status(401).json({ error: 'Login required' });

    const user = await getUser(userId);
    if (!user) return res.status(404).json({ error: 'User not found' });
    if (user.blocked) return res.status(403).json({ error: 'Your account is blocked by admin' });

    const round = await syncRoundState();
    if (!round) return res.status(500).json({ error: 'No active round' });

    const status = getStatusForRound(round);
    if (status !== 'open') return res.status(400).json({ error: 'Betting is closed for this round' });

    const validation = validateBetMap(req.body?.betMap);
    if (!validation.ok) return res.status(400).json({ error: validation.error });

    await placeBetTx(userId, Number(round.id), validation.sanitized, validation.total);

    return res.json({
      success: true,
      message: 'Bet placed successfully',
      state: await buildGameState(userId)
    });
  } catch (error) {
    return res.status(400).json({ error: error.message || 'Unable to place bet' });
  }
});

app.post('/api/claim-bonus', async (req, res) => {
  try {
    const userId = await getUserIdFromReq(req);
    if (!userId) return res.status(401).json({ error: 'Login required' });

    const user = await getUser(userId);
    if (!user) return res.status(404).json({ error: 'User not found' });
    if (user.blocked) return res.status(403).json({ error: 'Your account is blocked by admin' });

    const bonusAmount = await claimBonusTx(userId);
    return res.json({
      success: true,
      message: `Daily bonus claimed: +${bonusAmount}`,
      state: await buildGameState(userId)
    });
  } catch (error) {
    return res.status(400).json({ error: error.message || 'Unable to claim bonus' });
  }
});

async function uploadDepositProofToCloudinary(base64Image, username) {
  const safeImage = String(base64Image || '').trim();
  if (!safeImage) throw new Error('Screenshot image is missing');
  if (!safeImage.startsWith('data:image/')) throw new Error('Invalid screenshot image format');

  const result = await cloudinary.uploader.upload(safeImage, {
    folder: 'since1969zone/deposit-proofs',
    resource_type: 'image',
    public_id: `deposit_${String(username || 'user')}_${Date.now()}`
  });

  return result.secure_url || '';
}

app.post('/api/deposit-request', async (req, res) => {
  try {
    const userId = await getUserIdFromReq(req);
    if (!userId) return res.status(401).json({ error: 'Login required' });

    const user = await getUser(userId);
    if (!user) return res.status(404).json({ error: 'User not found' });
    if (user.blocked) return res.status(403).json({ error: 'Your account is blocked by admin' });

    const amount = Number(req.body?.amount);
    const method = String(req.body?.method || '').trim();
    const utr = String(req.body?.utr || '').trim();
    const screenshot = String(req.body?.screenshot || '').trim();

    if (!Number.isFinite(amount) || amount <= 0) return res.status(400).json({ error: 'Valid deposit amount required' });
    if (!method) return res.status(400).json({ error: 'Payment method required' });
    if (!utr && !screenshot) return res.status(400).json({ error: 'Provide UTR or screenshot proof' });
    if (!screenshot) return res.status(400).json({ error: 'Screenshot proof required' });

    const screenshotUrl = await uploadDepositProofToCloudinary(screenshot, user.username);
    const insertResult = await pool.query(
      `INSERT INTO deposit_requests (user_id, username, amount, method, utr, screenshot, status, archived, created_at, updated_at)
       VALUES ($1,$2,$3,$4,$5,$6,'pending',false,$7,NULL)
       RETURNING id`,
      [user.id, user.username, amount, method, utr, screenshotUrl, nowMs()]
    );

    await addTransaction(user.id, 'deposit_request', 0, {
      requestId: Number(insertResult.rows[0].id),
      amount,
      method,
      utr: utr || '',
      screenshot: screenshotUrl || ''
    });

    return res.json({
      success: true,
      message: 'Deposit request submitted successfully'
    });
  } catch (error) {
    console.error('DEPOSIT REQUEST ERROR:', error);
    return res.status(500).json({ error: error.message || 'Deposit request failed' });
  }
});

app.post('/api/withdrawal-request', async (req, res) => {
  try {
    const userId = await getUserIdFromReq(req);
    if (!userId) return res.status(401).json({ error: 'Login required' });

    const user = await getUser(userId);
    if (!user) return res.status(404).json({ error: 'User not found' });
    if (user.blocked) return res.status(403).json({ error: 'Your account is blocked by admin' });

    const amount = Number(req.body?.amount);
    const method = String(req.body?.method || '').trim();
    const details = req.body?.details || {};
    const upiId = String(details?.upiId || '').trim();

    if (!Number.isFinite(amount) || amount <= 0) return res.status(400).json({ error: 'Valid withdraw amount required' });
    if (!method) return res.status(400).json({ error: 'Withdrawal method required' });
    if (method === 'UPI' && !upiId) return res.status(400).json({ error: 'UPI ID required' });
    if (method === 'QR Code' && !String(details?.qrImage || '').trim()) return res.status(400).json({ error: 'QR image required' });

    if (method === 'Bank Account') {
      if (!String(details?.bankHolderName || '').trim()) return res.status(400).json({ error: 'Bank holder name required' });
      if (!String(details?.bankName || '').trim()) return res.status(400).json({ error: 'Bank name required' });
      if (!String(details?.ifscCode || '').trim()) return res.status(400).json({ error: 'IFSC code required' });
      if (!String(details?.accountNumber || '').trim()) return res.status(400).json({ error: 'Account number required' });
    }

    const playedCoins = Number(user.total_played || 0);
    const eligibleRequestBalance = calculateEligibleRequestBalance(user);

    if (amount < MIN_REQUEST_AMOUNT) {
      return res.status(400).json({ error: `Minimum withdrawal request is ${MIN_REQUEST_AMOUNT} coins` });
    }

    if (playedCoins < MIN_PLAY_BEFORE_REQUEST) {
      return res.status(400).json({ error: `Minimum ${MIN_PLAY_BEFORE_REQUEST} coin bet play first after withdrawal your winning amount and deposit amount balance` });
    }

    if (eligibleRequestBalance < MIN_REQUEST_AMOUNT) {
      return res.status(400).json({ error: `Minimum withdrawal ${MIN_REQUEST_AMOUNT} coin` });
    }

    if (amount > eligibleRequestBalance) return res.status(400).json({ error: 'Insufficient eligible request balance' });

    const pendingResult = await pool.query(
      `SELECT id FROM withdraw_requests WHERE user_id = $1 AND status = 'pending' LIMIT 1`,
      [user.id]
    );
    if (pendingResult.rows.length) {
      return res.status(400).json({ error: 'You already have a pending withdraw request' });
    }

    const insertResult = await pool.query(
      `INSERT INTO withdraw_requests (
        user_id, username, amount, method, upi_id, details, status, archived, created_at, updated_at
      )
      VALUES ($1,$2,$3,$4,$5,$6,'pending',false,$7,NULL)
      RETURNING id`,
      [user.id, user.username, amount, method, upiId, JSON.stringify(details || {}), nowMs()]
    );

    await addTransaction(user.id, 'withdraw_request', 0, {
      requestId: Number(insertResult.rows[0].id),
      amount,
      method,
      upiId,
      details: details || {}
    });

    return res.json({
      success: true,
      message: 'Withdraw request submitted',
      state: await buildGameState(userId)
    });
  } catch (error) {
    console.error('WITHDRAW REQUEST ERROR:', error);
    return res.status(500).json({ error: error.message || 'Withdraw failed' });
  }
});

app.get('/api/live-updates', async (req, res) => {
  const row = await getLiveUpdatesRow();
  const liveUpdates = row
    ? {
        paymentMethod: toJson(row.payment_method, { upiId: '', qrCodeImage: '', bankAccount: '' }),
        offer: String(row.offer || '')
      }
    : { paymentMethod: { upiId: '', qrCodeImage: '', bankAccount: '' }, offer: '' };

  return res.json({ success: true, liveUpdates });
});

app.get('/api/admin/live-updates', adminOnly, requireAdminRoles('super_admin', 'game_admin', 'read_only', 'finance_admin', 'support_admin'), async (req, res) => {
  const row = await getLiveUpdatesRow();
  const liveUpdates = row
    ? {
        paymentMethod: toJson(row.payment_method, { upiId: '', qrCodeImage: '', bankAccount: '' }),
        offer: String(row.offer || '')
      }
    : { paymentMethod: { upiId: '', qrCodeImage: '', bankAccount: '' }, offer: '' };

  return res.json({ success: true, liveUpdates });
});

app.post('/api/admin/live-updates', adminOnly, requireAdminRoles('super_admin', 'game_admin'), async (req, res) => {
  try {
    const section = String(req.body?.section || '').trim();
    const type = String(req.body?.type || '').trim();

    const row = await getLiveUpdatesRow();
    let paymentMethod = toJson(row?.payment_method, { upiId: '', qrCodeImage: '', bankAccount: '' });
    let offer = String(row?.offer || '');

    if (section === 'payment-method') {
      if (type === 'upi-id') paymentMethod.upiId = String(req.body?.upiId || '').trim();
      if (type === 'qr-code') paymentMethod.qrCodeImage = String(req.body?.qrCodeImage || '').trim();
      if (type === 'bank-account') paymentMethod.bankAccount = String(req.body?.bankAccount || '').trim();
    }

    if (section === 'offer') {
      offer = String(req.body?.offer || '').trim();
    }

    await pool.query(
      `UPDATE live_updates SET payment_method = $1, offer = $2 WHERE id = $3`,
      [JSON.stringify(paymentMethod), offer, row.id]
    );

    return res.json({
      success: true,
      message: 'Live updates saved successfully',
      liveUpdates: { paymentMethod, offer }
    });
  } catch (error) {
    console.error('LIVE UPDATES SAVE ERROR:', error);
    return res.status(500).json({ error: 'Unable to save live updates' });
  }
});


app.get('/api/admin/dashboard-stats', adminOnly, requireAdminRoles('super_admin', 'finance_admin', 'game_admin', 'support_admin', 'read_only'), async (req, res) => {
  try {
    const range = getAdminRangeFromQuery(req.query || {});
    const [usersCount, pendingDep, pendingWit, activeUsers, totalDep, totalWit, betsCurrent, winsCurrent, betsPrevious, topDepositor, topWinner] = await Promise.all([
      pool.query(`SELECT COUNT(*)::int AS count FROM users WHERE is_admin = false`),
      pool.query(`SELECT COUNT(*)::int AS count FROM deposit_requests WHERE status = 'pending'`),
      pool.query(`SELECT COUNT(*)::int AS count FROM withdraw_requests WHERE status = 'pending'`),
      pool.query(`SELECT COUNT(DISTINCT id)::int AS count FROM users WHERE is_admin = false AND COALESCE(last_active_at,0) BETWEEN $1 AND $2`, [range.from, range.to]),
      pool.query(`SELECT COALESCE(SUM(amount),0) AS total FROM transactions WHERE type = 'deposit_approved' AND created_at BETWEEN $1 AND $2`, [range.from, range.to]),
      pool.query(`SELECT COALESCE(SUM(ABS(amount)),0) AS total FROM transactions WHERE type = 'withdrawal_approved' AND created_at BETWEEN $1 AND $2`, [range.from, range.to]),
      pool.query(`SELECT COUNT(*)::int AS count FROM bets WHERE created_at BETWEEN $1 AND $2`, [range.from, range.to]),
      pool.query(`SELECT COUNT(*)::int AS count FROM bets WHERE created_at BETWEEN $1 AND $2 AND result = 'win'`, [range.from, range.to]),
      pool.query(`SELECT COUNT(*)::int AS count FROM bets WHERE created_at BETWEEN $1 AND $2`, [range.previousFrom, range.previousTo]),
      pool.query(`SELECT u.username, COALESCE(SUM(t.amount),0) AS total FROM transactions t JOIN users u ON u.id=t.user_id WHERE t.type='deposit_approved' AND u.is_admin=false AND t.created_at BETWEEN $1 AND $2 GROUP BY u.username ORDER BY total DESC, u.username ASC LIMIT 1`, [range.from, range.to]),
      pool.query(`SELECT u.username, COALESCE(SUM(t.amount),0) AS total FROM transactions t JOIN users u ON u.id=t.user_id WHERE t.type='win_credit' AND u.is_admin=false AND t.created_at BETWEEN $1 AND $2 GROUP BY u.username ORDER BY total DESC, u.username ASC LIMIT 1`, [range.from, range.to])
    ]);
    const totalDeposits = Number(totalDep.rows[0]?.total || 0);
    const totalWithdrawals = Number(totalWit.rows[0]?.total || 0);
    return res.json({ success: true, filter: { preset: range.preset, from: Number(range.from), to: Number(range.to), serverNow: nowMs() }, stats: { totalDeposits, totalWithdrawals, profitLoss: totalDeposits - totalWithdrawals, totalUsers: Number(usersCount.rows[0]?.count || 0), activeUsers24h: Number(activeUsers.rows[0]?.count || 0), totalBetsToday: Number(betsCurrent.rows[0]?.count || 0), totalWinsToday: Number(winsCurrent.rows[0]?.count || 0), pendingRequests: Number(pendingDep.rows[0]?.count || 0) + Number(pendingWit.rows[0]?.count || 0), topDepositor: topDepositor.rows[0] ? { username: topDepositor.rows[0].username, amount: Number(topDepositor.rows[0].total || 0) } : null, topWinner: topWinner.rows[0] ? { username: topWinner.rows[0].username, amount: Number(topWinner.rows[0].total || 0) } : null, todayVsYesterday: { today: Number(betsCurrent.rows[0]?.count || 0), yesterday: Number(betsPrevious.rows[0]?.count || 0) } } });
  } catch (error) {
    console.error('DASHBOARD STATS ERROR:', error);
    return res.status(500).json({ error: 'Unable to load dashboard stats' });
  }
});

app.get('/api/admin/load-users', adminOnly, requireAdminRoles('super_admin', 'finance_admin', 'support_admin', 'read_only', 'game_admin'), async (req, res) => {
  const result = await pool.query(
    `SELECT id, username, wallet_balance, bonus_balance, deposit_balance, winning_balance, total_played, total_wins, bonus_claimed, blocked, created_at
     FROM users
     WHERE is_admin = false
     ORDER BY id DESC`
  );

  const users = result.rows.map(user => ({
    id: Number(user.id),
    username: user.username,
    walletBalance: Number(user.wallet_balance || 0),
    mainBalance: Number(user.wallet_balance || 0),
    bonusBalance: Number(user.bonus_balance || 0),
    depositBalance: Number(user.deposit_balance || 0),
    winningBalance: Number(user.winning_balance || 0),
    eligibleRequestBalance: Number(user.deposit_balance || 0) + Number(user.winning_balance || 0),
    totalPlayed: Number(user.total_played || 0),
    totalWins: Number(user.total_wins || 0),
    bonusClaimed: Number(user.bonus_claimed || 0),
    blocked: Boolean(user.blocked),
    createdAt: Number(user.created_at || 0)
  }));

  return res.json({ users });
});

app.post('/api/admin/add-coin', adminOnly, requireAdminRoles('super_admin', 'finance_admin'), async (req, res) => {
  try {
    const userId = Number(req.body?.userId);
    const amount = Number(req.body?.amount);
    const walletType = String(req.body?.walletType || 'deposit').trim().toLowerCase();

    if (!Number.isInteger(userId) || userId <= 0) return res.status(400).json({ error: 'Valid userId required' });
    if (!Number.isFinite(amount) || amount <= 0) return res.status(400).json({ error: 'Valid amount required' });
    if (!['bonus', 'deposit'].includes(walletType)) return res.status(400).json({ error: 'Valid wallet type required' });

    const user = await getUser(userId);
    if (!user || user.is_admin === true) return res.status(404).json({ error: 'User not found' });

    const increments = {
      wallet_balance: amount,
      [walletType === 'bonus' ? 'bonus_balance' : 'deposit_balance']: amount
    };

    await incrementUserFields(user.id, increments);
    await addTransaction(user.id, 'admin_add_coin', amount, { adminId: req.user.id, walletType });

    const refreshed = await refreshMainBalance(user.id);
    await logAdminActivity(req.user, 'admin_add_coin', user, { amount, walletType });

    return res.json({
      success: true,
      message: `${amount} ${walletType} coins added to ${user.username}`,
      user: {
        id: Number(refreshed.id),
        username: refreshed.username,
        walletBalance: Number(refreshed.wallet_balance || 0),
        bonusBalance: Number(refreshed.bonus_balance || 0),
        depositBalance: Number(refreshed.deposit_balance || 0),
        winningBalance: Number(refreshed.winning_balance || 0)
      }
    });
  } catch (error) {
    console.error('ADMIN ADD COIN ERROR:', error);
    return res.status(500).json({ error: 'Unable to add coins' });
  }
});

app.post('/api/admin/withdraw-coin', adminOnly, requireAdminRoles('super_admin', 'finance_admin'), async (req, res) => {
  try {
    const userId = Number(req.body?.userId);
    const amount = Number(req.body?.amount);
    const walletType = String(req.body?.walletType || 'deposit').trim().toLowerCase();

    if (!Number.isInteger(userId) || userId <= 0) return res.status(400).json({ error: 'Valid userId required' });
    if (!Number.isFinite(amount) || amount <= 0) return res.status(400).json({ error: 'Valid amount required' });
    if (!['bonus', 'deposit', 'winning'].includes(walletType)) return res.status(400).json({ error: 'Valid wallet type required' });

    const user = await refreshMainBalance(userId);
    if (!user || user.is_admin === true) return res.status(404).json({ error: 'User not found' });

    const selectedWalletKey = `${walletType}_balance`;
    const selectedWalletAmount = Number(user[selectedWalletKey] || 0);
    if (selectedWalletAmount < amount) {
      return res.status(400).json({ error: `${walletType} wallet has insufficient balance` });
    }

    await incrementUserFields(user.id, {
      wallet_balance: -amount,
      [selectedWalletKey]: -amount
    });
    await addTransaction(user.id, 'admin_withdraw_coin', -amount, {
      adminId: req.user.id,
      walletType,
      bonusUsed: walletType === 'bonus' ? amount : 0,
      depositUsed: walletType === 'deposit' ? amount : 0,
      winningUsed: walletType === 'winning' ? amount : 0
    });

    const refreshed = await refreshMainBalance(user.id);
    await logAdminActivity(req.user, 'admin_withdraw_coin', user, { amount, walletType });

    return res.json({
      success: true,
      message: `${amount} ${walletType} coins removed from ${user.username}`,
      user: {
        id: Number(refreshed.id),
        username: refreshed.username,
        walletBalance: Number(refreshed.wallet_balance || 0),
        bonusBalance: Number(refreshed.bonus_balance || 0),
        depositBalance: Number(refreshed.deposit_balance || 0),
        winningBalance: Number(refreshed.winning_balance || 0),
        blocked: Boolean(refreshed.blocked)
      }
    });
  } catch (error) {
    console.error('ADMIN WITHDRAW COIN ERROR:', error);
    return res.status(500).json({ error: 'Unable to withdraw coins' });
  }
});

app.post('/api/admin/block-user', adminOnly, requireAdminRoles('super_admin', 'support_admin'), async (req, res) => {
  try {
    const userId = Number(req.body?.userId);
    if (!Number.isInteger(userId) || userId <= 0) return res.status(400).json({ error: 'Valid userId required' });

    const user = await getUser(userId);
    if (!user || user.is_admin === true) return res.status(404).json({ error: 'User not found' });

    const nextBlocked = !Boolean(user.blocked);
    await setUserBlockedStatus(user.id, nextBlocked);

    return res.json({
      success: true,
      message: nextBlocked ? `${user.username} blocked` : `${user.username} unblocked`,
      blocked: nextBlocked
    });
  } catch (error) {
    console.error('BLOCK USER ERROR:', error);
    return res.status(500).json({ error: 'Failed to update block status' });
  }
});

app.post('/api/admin/delete-user', adminOnly, requireAdminRoles('super_admin'), async (req, res) => {
  try {
    const userId = Number(req.body?.userId);
    if (!Number.isInteger(userId) || userId <= 0) return res.status(400).json({ error: 'Valid userId required' });

    const user = await getUser(userId);
    if (!user || user.is_admin === true) return res.status(404).json({ error: 'User not found' });

    const deletedUsersData = loadDeletedUsersData();
    deletedUsersData.deletedUsers.push({
      ...user,
      deleted_at: nowMs()
    });
    saveDeletedUsersData(deletedUsersData);

    await pool.query(`DELETE FROM bets WHERE user_id = $1`, [userId]);
    await pool.query(`DELETE FROM transactions WHERE user_id = $1`, [userId]);
    await pool.query(`DELETE FROM deposit_requests WHERE user_id = $1`, [userId]);
    await pool.query(`DELETE FROM withdraw_requests WHERE user_id = $1`, [userId]);
    await deleteUserById(userId);

    return res.json({
      success: true,
      message: `${user.username} deleted successfully`
    });
  } catch (error) {
    console.error('DELETE USER ERROR:', error);
    return res.status(500).json({ error: 'Unable to delete user' });
  }
});

app.get('/api/admin/transaction-history', adminOnly, requireAdminRoles('super_admin', 'finance_admin', 'support_admin', 'read_only', 'game_admin'), async (req, res) => {
  const range = getAdminRangeFromQuery(req.query || {});
  const walletType = String(req.query?.walletType || '').trim().toLowerCase();
  const result = await pool.query(
    `SELECT * FROM transactions WHERE type IN ('admin_add_coin', 'admin_withdraw_coin') AND COALESCE(meta->>'adminId', '') = $1 AND created_at BETWEEN $2 AND $3 AND ($4 = '' OR LOWER(COALESCE(meta->>'walletType','')) = $4) ORDER BY created_at DESC LIMIT 1000`,
    [String(req.user.id), range.from, range.to, walletType]
  );
  const history = [];
  for (const item of result.rows) {
    const targetUser = await getUser(item.user_id);
    history.push({
      id: Number(item.id),
      userId: Number(item.user_id),
      username: targetUser?.username || 'Deleted User',
      type: item.type,
      amount: Number(item.amount || 0),
      meta: toJson(item.meta, {}),
      createdAt: Number(item.created_at || 0)
    });
  }
  return res.json({ history });
});

app.get('/api/admin/deposit-requests', adminOnly, requireAdminRoles('super_admin', 'finance_admin', 'read_only'), async (req, res) => {
  const range = getAdminRangeFromQuery(req.query || {});
  const statusFilter = String(req.query?.status || '').trim().toLowerCase();
  const depositResult = await pool.query(`SELECT * FROM deposit_requests WHERE created_at BETWEEN $1 AND $2 AND ($3 = '' OR LOWER(status) = $3)`, [range.from, range.to, statusFilter]);
  const withdrawResult = await pool.query(`SELECT * FROM withdraw_requests WHERE created_at BETWEEN $1 AND $2 AND ($3 = '' OR LOWER(status) = $3)`, [range.from, range.to, statusFilter]);

  const depositRequests = depositResult.rows.map(item => ({
    id: Number(item.id),
    type: 'deposit',
    userId: Number(item.user_id),
    username: item.username,
    amount: Number(item.amount || 0),
    method: item.method || '',
    utr: item.utr || '',
    screenshot: item.screenshot || '',
    status: item.status,
    createdAt: Number(item.created_at || 0),
    updatedAt: item.updated_at ? Number(item.updated_at) : null
  }));

  const withdrawalRequests = withdrawResult.rows.map(item => ({
    id: Number(item.id),
    type: 'withdrawal',
    userId: Number(item.user_id),
    username: item.username,
    amount: Number(item.amount || 0),
    method: item.method || '',
    withdrawal_details: toJson(item.details, {}),
    upiId: item.upi_id || '',
    status: item.status,
    createdAt: Number(item.created_at || 0),
    updatedAt: item.updated_at ? Number(item.updated_at) : null
  }));

  const requests = [...depositRequests, ...withdrawalRequests]
    .sort((a, b) => (b.createdAt || 0) - (a.createdAt || 0));

  return res.json({ requests });
});

app.post('/api/admin/deposit-requests/action', adminOnly, requireAdminRoles('super_admin', 'finance_admin'), async (req, res) => {
  try {
    const requestId = Number(req.body?.requestId);
    const action = String(req.body?.action || '').trim().toLowerCase();
    const type = String(req.body?.type || '').trim().toLowerCase();

    if (!Number.isInteger(requestId) || requestId <= 0) return res.status(400).json({ error: 'Valid requestId required' });
    if (!['approve', 'reject'].includes(action)) return res.status(400).json({ error: 'Valid action required' });
    if (!['deposit', 'withdrawal'].includes(type)) return res.status(400).json({ error: 'Valid request type required' });

    if (type === 'deposit') {
      const requestResult = await pool.query(`SELECT * FROM deposit_requests WHERE id = $1 LIMIT 1`, [requestId]);
      const request = requestResult.rows[0];
      if (!request) return res.status(404).json({ error: 'Deposit request not found' });
      if (request.status !== 'pending') return res.status(400).json({ error: 'This deposit request is already processed' });

      const user = await getUser(request.user_id);
      if (!user) return res.status(404).json({ error: 'User not found' });

      const nextStatus = action === 'approve' ? 'approved' : 'rejected';
      await pool.query(
        `UPDATE deposit_requests SET status = $1, updated_at = $2 WHERE id = $3`,
        [nextStatus, nowMs(), request.id]
      );

      if (action === 'approve') {
        await incrementUserFields(user.id, { wallet_balance: Number(request.amount || 0), deposit_balance: Number(request.amount || 0) });
        await addTransaction(user.id, 'deposit_approved', Number(request.amount || 0), {
          requestId: Number(request.id),
          adminId: Number(req.user.id),
          walletType: 'deposit'
        });
      }

      if (action === 'reject') {
        await addTransaction(user.id, 'deposit_rejected', 0, {
          requestId: Number(request.id),
          adminId: Number(req.user.id)
        });
      }

      return res.json({
        success: true,
        message: action === 'approve'
          ? 'Deposit request approved successfully'
          : 'Deposit request rejected successfully',
        request: { ...request, status: nextStatus, updated_at: nowMs() }
      });
    }

    if (type === 'withdrawal') {
      const requestResult = await pool.query(`SELECT * FROM withdraw_requests WHERE id = $1 LIMIT 1`, [requestId]);
      const request = requestResult.rows[0];
      if (!request) return res.status(404).json({ error: 'Withdrawal request not found' });
      if (request.status !== 'pending') return res.status(400).json({ error: 'This withdrawal request is already processed' });

      const user = await getUser(request.user_id);
      if (!user) return res.status(404).json({ error: 'User not found' });

      if (action === 'approve' && calculateEligibleRequestBalance(user) < Number(request.amount || 0)) {
        return res.status(400).json({ error: 'User has insufficient eligible request balance for approval' });
      }

      const nextStatus = action === 'approve' ? 'approved' : 'rejected';
      await pool.query(
        `UPDATE withdraw_requests SET status = $1, updated_at = $2 WHERE id = $3`,
        [nextStatus, nowMs(), request.id]
      );

      if (action === 'approve') {
        const usage = splitRequestDeduction(user, Number(request.amount || 0));
        if (!usage.success) {
          return res.status(400).json({ error: usage.message || 'Unable to approve withdrawal' });
        }

        await incrementUserFields(user.id, {
          wallet_balance: -Number(request.amount || 0),
          deposit_balance: -Number(usage.depositUsed || 0),
          winning_balance: -Number(usage.winningUsed || 0)
        });
        await addTransaction(user.id, 'withdrawal_approved', -Number(request.amount || 0), {
          requestId: Number(request.id),
          adminId: Number(req.user.id),
          method: request.method || '',
          upiId: request.upi_id || '',
          details: toJson(request.details, {}),
          depositUsed: Number(usage.depositUsed || 0),
          winningUsed: Number(usage.winningUsed || 0)
        });
      }

      if (action === 'reject') {
        await addTransaction(user.id, 'withdraw_rejected', 0, {
          requestId: Number(request.id),
          adminId: Number(req.user.id),
          method: request.method || '',
          upiId: request.upi_id || '',
          details: toJson(request.details, {})
        });
      }

      return res.json({
        success: true,
        message: action === 'approve'
          ? 'Withdrawal request approved successfully'
          : 'Withdrawal request rejected successfully',
        request: { ...request, status: nextStatus, updated_at: nowMs() }
      });
    }

    return res.status(400).json({ error: 'Invalid request type' });
  } catch (error) {
    console.error('REQUEST ACTION ERROR:', error);
    return res.status(500).json({ error: 'Unable to update request' });
  }
});

app.get('/api/admin/current-round', adminOnly, requireAdminRoles('super_admin', 'game_admin', 'read_only', 'finance_admin', 'support_admin'), async (req, res) => {
  try {
    const round = await syncRoundState();
    if (!round) return res.status(404).json({ error: 'No active round found' });

    const relatedBetsResult = await pool.query(`SELECT * FROM bets WHERE round_id = $1`, [round.id]);
    const relatedBets = relatedBetsResult.rows;

    return res.json({
      round: {
        id: Number(round.id),
        roundNumber: Number(round.round_number),
        roundCode: round.round_code || '-',
        status: getStatusForRound(round),
        startsAt: Number(round.starts_at),
        bettingClosesAt: Number(round.betting_closes_at),
        endsAt: Number(round.ends_at),
        serverSeedHash: round.server_seed_hash,
        clientSeed: round.client_seed,
        totalBets: relatedBets.length,
        totalCoins: relatedBets.reduce((sum, bet) => sum + Number(bet.total_coins || 0), 0)
      }
    });
  } catch (error) {
    console.error('CURRENT ROUND ERROR:', error);
    return res.status(500).json({ error: 'Unable to load current round' });
  }
});

app.post('/api/admin/force-settle-round', adminOnly, requireAdminRoles('super_admin', 'game_admin'), async (req, res) => {
  try {
    const round = await getCurrentRound();
    if (!round) return res.status(404).json({ error: 'No active round found' });

    await pool.query(`UPDATE rounds SET ends_at = LEAST(ends_at, $1) WHERE id = $2`, [nowMs(), round.id]);
    await settleRoundTx(round.id);
    await createNextRoundIfNeeded();

    return res.json({ success: true, message: 'Round settled successfully' });
  } catch (error) {
    console.error('FORCE SETTLE ERROR:', error);
    return res.status(400).json({ error: error.message || 'Unable to settle round' });
  }
});

app.get('/api/admin/user-history/:username', adminOnly, requireAdminRoles('super_admin', 'support_admin', 'read_only', 'finance_admin'), async (req, res) => {
  try {
    const username = String(req.params.username || '').trim();
    if (!username) return res.status(400).json({ error: 'Username required' });

    const user = await getUserByUsername(username);
    if (!user) return res.status(404).json({ error: 'User not found' });

    const betsResult = await pool.query(`SELECT * FROM bets WHERE user_id = $1 ORDER BY created_at DESC`, [user.id]);
    const roundsResult = await pool.query(`SELECT * FROM rounds`);
    const roundMap = new Map(roundsResult.rows.map(r => [Number(r.id), r]));

    const bets = betsResult.rows.map(bet => {
      const round = roundMap.get(Number(bet.round_id));
      return {
        id: Number(bet.id),
        roundId: Number(bet.round_id),
        roundNumber: round ? Number(round.round_number) : null,
        roundCode: round?.round_code || '-',
        betMap: toJson(bet.bet_map, {}),
        totalCoins: Number(bet.total_coins || 0),
        matchedNumber: bet.matched_number === null ? null : Number(bet.matched_number),
        payout: Number(bet.payout || 0),
        result: bet.result || '-',
        createdAt: Number(bet.created_at || 0)
      };
    });

    const txResult = await pool.query(`SELECT * FROM transactions WHERE user_id = $1 ORDER BY created_at DESC`, [user.id]);
    const transactions = txResult.rows.map(tx => ({
      id: Number(tx.id),
      type: tx.type,
      amount: Number(tx.amount || 0),
      meta: toJson(tx.meta, {}),
      createdAt: Number(tx.created_at || 0)
    }));

    const depResult = await pool.query(`SELECT * FROM deposit_requests WHERE user_id = $1`, [user.id]);
    const witResult = await pool.query(`SELECT * FROM withdraw_requests WHERE user_id = $1`, [user.id]);

    const depositHistory = depResult.rows.map(r => ({
      id: Number(r.id),
      type: 'deposit',
      amount: Number(r.amount || 0),
      method: r.method || '',
      utr: r.utr || '',
      screenshot: r.screenshot || '',
      status: r.status,
      createdAt: Number(r.created_at || 0),
      updatedAt: r.updated_at ? Number(r.updated_at) : null
    }));

    const withdrawalHistory = witResult.rows.map(r => ({
      id: Number(r.id),
      type: 'withdrawal',
      amount: Number(r.amount || 0),
      method: r.method || '',
      utr: '',
      screenshot: '',
      status: r.status,
      withdrawal_details: toJson(r.details, {}),
      createdAt: Number(r.created_at || 0),
      updatedAt: r.updated_at ? Number(r.updated_at) : null
    }));

    const requests = [...depositHistory, ...withdrawalHistory]
      .sort((a, b) => (b.createdAt || 0) - (a.createdAt || 0));

    return res.json({
      success: true,
      user: {
        id: Number(user.id),
        username: user.username,
        walletBalance: Number(user.wallet_balance || 0),
        totalPlayed: Number(user.total_played || 0),
        totalWins: Number(user.total_wins || 0),
        bonusClaimed: Number(user.bonus_claimed || 0),
        blocked: !!user.blocked,
        isAdmin: !!user.is_admin,
        createdAt: Number(user.created_at || 0)
      },
      history: { bets, transactions, requests }
    });
  } catch (error) {
    console.error('USER HISTORY ERROR:', error);
    return res.status(500).json({ error: 'Unable to load user history' });
  }
});

app.get('/api/wallet-history', async (req, res) => {
  try {
    const userId = await getUserIdFromReq(req);
    if (!userId) return res.status(401).json({ error: 'Login required' });

    const user = await getUser(userId);
    if (!user) return res.status(404).json({ error: 'User not found' });

    const depResult = await pool.query(
      `SELECT * FROM deposit_requests WHERE user_id = $1 ORDER BY created_at DESC`,
      [user.id]
    );
    const witResult = await pool.query(
      `SELECT * FROM withdraw_requests WHERE user_id = $1 ORDER BY created_at DESC`,
      [user.id]
    );
    const txResult = await pool.query(
      `SELECT * FROM transactions WHERE user_id = $1 ORDER BY created_at DESC LIMIT 200`,
      [user.id]
    );

    const requestItems = [
      ...depResult.rows.map(request => ({
        id: `deposit-request-${request.id}`,
        title: 'Deposit Request',
        amount: Math.abs(Number(request.amount || 0)),
        direction: 'request_deposit',
        details: request.utr
          ? `UTR: ${request.utr}`
          : (request.method ? `Method: ${request.method}` : 'Deposit request submitted'),
        status: String(request.status || 'pending').toLowerCase(),
        createdAt: request.created_at ? Number(request.created_at) : null,
        updatedAt: request.updated_at ? Number(request.updated_at) : null,
        group: 'request'
      })),
      ...witResult.rows.map(request => ({
        id: `withdraw-request-${request.id}`,
        title: 'Withdrawal Request',
        amount: Math.abs(Number(request.amount || 0)),
        direction: 'debit',
        details: request.upi_id
          ? `UPI ID: ${request.upi_id}`
          : (request.method ? `Method: ${request.method}` : 'Withdrawal request submitted'),
        status: String(request.status || 'pending').toLowerCase(),
        createdAt: request.created_at ? Number(request.created_at) : null,
        updatedAt: request.updated_at ? Number(request.updated_at) : null,
        group: 'request'
      }))
    ];

    const hiddenTxTypes = new Set([
      'deposit_request',
      'withdraw_request',
      'deposit_rejected',
      'withdrawal_approved',
      'withdraw_rejected_refund',
      'withdraw_rejected'
    ]);

    const transactionItems = txResult.rows
      .filter(tx => !hiddenTxTypes.has(String(tx.type || '')))
      .map(tx => {
        const meta = toJson(tx.meta, {});
        let title = 'Wallet Activity';
        let details = 'Wallet activity';

        const amount = Math.abs(Number(tx.amount || 0));
        const direction = Number(tx.amount || 0) >= 0 ? 'credit' : 'debit';

        if (tx.type === 'deposit_approved') {
          title = 'Deposit Approved';
          details = 'Coins added to deposit balance by admin approval';
        } else if (tx.type === 'bet_debit') {
          title = 'Bet Placed / Loss';
          details = meta.roundId ? `Round ID: ${meta.roundId} | Bonus ${Number(meta.bonusUsed || 0)} | Deposit ${Number(meta.depositUsed || 0)} | Winning ${Number(meta.winningUsed || 0)}` : 'Bet amount deducted';
        } else if (tx.type === 'win_credit') {
          title = 'Winning Credit';
          details = meta.luckyNumber !== undefined ? `Lucky Number: ${meta.luckyNumber}` : 'Winning amount added';
        } else if (tx.type === 'bonus_credit') {
          title = 'Daily Bonus';
          details = 'Bonus credited to bonus balance';
        } else if (tx.type === 'admin_add_coin') {
          title = 'Admin Added Coins';
          details = `Coins added by admin to ${String(meta.walletType || 'deposit')} balance`;
        } else if (tx.type === 'admin_withdraw_coin') {
          title = 'Admin Removed Coins';
          details = `Coins removed by admin | Bonus ${Number(meta.bonusUsed || 0)} | Deposit ${Number(meta.depositUsed || 0)} | Winning ${Number(meta.winningUsed || 0)}`;
        }

        return {
          id: Number(tx.id),
          title,
          amount,
          direction,
          details,
          status: '',
          createdAt: tx.created_at ? Number(tx.created_at) : null,
          updatedAt: null,
          group: 'transaction'
        };
      });

    const items = [...requestItems, ...transactionItems]
      .sort((a, b) => Number(b.createdAt || 0) - Number(a.createdAt || 0))
      .slice(0, 200)
      .map(item => ({
        ...item,
        statusLabel: item.status
          ? item.status.charAt(0).toUpperCase() + item.status.slice(1)
          : ''
      }));

    return res.json({ success: true, history: items });
  } catch (error) {
    console.error('WALLET HISTORY ERROR:', error);
    return res.status(500).json({ error: 'Failed to load wallet history' });
  }
});



app.get('/api/admin/admins', adminOnly, requireAdminRoles('super_admin'), async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT id, username, blocked, is_admin, admin_role, last_active_at, created_at
       FROM users
       WHERE is_admin = true
       ORDER BY id ASC`
    );

    return res.json({
      success: true,
      admins: result.rows.map(row => ({
        id: Number(row.id),
        username: String(row.username || ''),
        blocked: Boolean(row.blocked),
        isAdmin: Boolean(row.is_admin),
        role: normalizeAdminRole(row.admin_role, true),
        lastActiveAt: Number(row.last_active_at || 0),
        createdAt: Number(row.created_at || 0)
      }))
    });
  } catch (error) {
    console.error('ADMIN LIST ERROR:', error);
    return res.status(500).json({ error: 'Unable to load admins' });
  }
});

app.post('/api/admin/create-admin', adminOnly, requireAdminRoles('super_admin'), async (req, res) => {
  try {
    const username = sanitizeAdminUsername(req.body?.username);
    const password = sanitizeAdminPassword(req.body?.password);
    const role = normalizeAdminRole(req.body?.role, true);

    if (!username) return res.status(400).json({ error: 'Admin username required' });
    if (!password || password.length < 4) return res.status(400).json({ error: 'Admin password minimum 4 characters' });

    const existing = await getUserByUsername(username);
    if (existing) return res.status(409).json({ error: 'Username already exists' });

    const adminUser = await createUserRecord({
      username,
      password: `sha256$${hashPassword(password)}`,
      walletBalance: 0,
      bonusBalance: 0,
      depositBalance: 0,
      winningBalance: 0,
      isAdmin: true
    });

    await updateUserFields(adminUser.id, { admin_role: role, blocked: false, wallet_balance: 0, bonus_balance: 0, deposit_balance: 0, winning_balance: 0 });
    await logAdminActivity(req.user, 'create_admin', adminUser, { role });

    return res.json({ success: true, message: 'Admin created successfully' });
  } catch (error) {
    console.error('CREATE ADMIN ERROR:', error);
    return res.status(500).json({ error: 'Unable to create admin' });
  }
});

app.post('/api/admin/update-admin-role', adminOnly, requireAdminRoles('super_admin'), async (req, res) => {
  try {
    const adminId = Number(req.body?.adminId);
    const role = normalizeAdminRole(req.body?.role, true);
    if (!Number.isInteger(adminId) || adminId <= 0) return res.status(400).json({ error: 'Valid adminId required' });

    const adminUser = await getUser(adminId);
    if (!adminUser || adminUser.is_admin !== true) return res.status(404).json({ error: 'Admin not found' });

    await updateUserFields(adminUser.id, { admin_role: role });
    await logAdminActivity(req.user, 'update_admin_role', adminUser, { role });
    return res.json({ success: true, message: 'Admin role updated' });
  } catch (error) {
    console.error('UPDATE ADMIN ROLE ERROR:', error);
    return res.status(500).json({ error: 'Unable to update admin role' });
  }
});

app.post('/api/admin/toggle-admin-block', adminOnly, requireAdminRoles('super_admin'), async (req, res) => {
  try {
    const adminId = Number(req.body?.adminId);
    if (!Number.isInteger(adminId) || adminId <= 0) return res.status(400).json({ error: 'Valid adminId required' });
    if (Number(req.user?.id) === adminId) return res.status(400).json({ error: 'You cannot block yourself' });

    const adminUser = await getUser(adminId);
    if (!adminUser || adminUser.is_admin !== true) return res.status(404).json({ error: 'Admin not found' });

    const nextBlocked = !Boolean(adminUser.blocked);
    await updateUserFields(adminUser.id, { blocked: nextBlocked });
    await logAdminActivity(req.user, nextBlocked ? 'block_admin' : 'unblock_admin', adminUser, {});
    return res.json({ success: true, message: nextBlocked ? 'Admin blocked' : 'Admin unblocked' });
  } catch (error) {
    console.error('TOGGLE ADMIN BLOCK ERROR:', error);
    return res.status(500).json({ error: 'Unable to update admin status' });
  }
});

app.post('/api/admin/reset-admin-password', adminOnly, requireAdminRoles('super_admin'), async (req, res) => {
  try {
    const adminId = Number(req.body?.adminId);
    const password = sanitizeAdminPassword(req.body?.password);
    if (!Number.isInteger(adminId) || adminId <= 0) return res.status(400).json({ error: 'Valid adminId required' });
    if (!password || password.length < 4) return res.status(400).json({ error: 'New password minimum 4 characters' });

    const adminUser = await getUser(adminId);
    if (!adminUser || adminUser.is_admin !== true) return res.status(404).json({ error: 'Admin not found' });

    await updateUserFields(adminUser.id, { password: `sha256$${hashPassword(password)}`, session_token: '' });
    await logAdminActivity(req.user, 'reset_admin_password', adminUser, {});
    return res.json({ success: true, message: 'Admin password reset successfully' });
  } catch (error) {
    console.error('RESET ADMIN PASSWORD ERROR:', error);
    return res.status(500).json({ error: 'Unable to reset admin password' });
  }
});

app.post('/api/admin/delete-admin', adminOnly, requireAdminRoles('super_admin'), async (req, res) => {
  try {
    const adminId = Number(req.body?.adminId);
    if (!Number.isInteger(adminId) || adminId <= 0) return res.status(400).json({ error: 'Valid adminId required' });
    if (Number(req.user?.id) === adminId) return res.status(400).json({ error: 'You cannot delete yourself' });

    const adminUser = await getUser(adminId);
    if (!adminUser || adminUser.is_admin !== true) return res.status(404).json({ error: 'Admin not found' });
    if (normalizeAdminRole(adminUser.admin_role, true) === 'super_admin') {
      const superCount = await pool.query(`SELECT COUNT(*)::int AS count FROM users WHERE is_admin = true AND COALESCE(admin_role, 'super_admin') = 'super_admin'`);
      if (Number(superCount.rows[0]?.count || 0) <= 1) return res.status(400).json({ error: 'Last super admin cannot be deleted' });
    }

    await logAdminActivity(req.user, 'delete_admin', adminUser, {});
    await deleteUserById(adminUser.id);
    return res.json({ success: true, message: 'Admin deleted successfully' });
  } catch (error) {
    console.error('DELETE ADMIN ERROR:', error);
    return res.status(500).json({ error: 'Unable to delete admin' });
  }
});

app.get('/api/admin/activity-logs', adminOnly, requireAdminRoles('super_admin'), async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT * FROM admin_activity_logs ORDER BY created_at DESC LIMIT 10`
    );
    return res.json({
      success: true,
      logs: result.rows.map(row => ({
        id: Number(row.id),
        adminUserId: Number(row.admin_user_id || 0),
        adminUsername: String(row.admin_username || ''),
        action: String(row.action || ''),
        targetUserId: row.target_user_id === null ? null : Number(row.target_user_id),
        targetUsername: String(row.target_username || ''),
        meta: toJson(row.meta, {}),
        createdAt: Number(row.created_at || 0)
      }))
    });
  } catch (error) {
    console.error('ADMIN ACTIVITY LOGS ERROR:', error);
    return res.status(500).json({ error: 'Unable to load admin activity logs' });
  }
});

/* Compatibility aliases for existing frontend/admin */
app.post('/api/bet', (req, res) => app._router.handle({ ...req, url: '/api/place-bet', method: 'POST' }, res, () => {}));
app.post('/api/bonus', (req, res) => app._router.handle({ ...req, url: '/api/claim-bonus', method: 'POST' }, res, () => {}));
app.get('/api/admin/users', (req, res) => app._router.handle({ ...req, url: '/api/admin/load-users', method: 'GET' }, res, () => {}));

app.post('/api/admin/add-coins', async (req, res) => {
  const username = String(req.body?.username || '').trim();
  const amount = req.body?.amount;
  const walletType = String(req.body?.walletType || 'deposit').trim().toLowerCase();
  const user = await getUserByUsername(username);
  if (!user || user.is_admin === true) return res.status(404).json({ error: 'User not found' });
  req.body = { userId: Number(user.id), amount, walletType };
  return app._router.handle({ ...req, url: '/api/admin/add-coin', method: 'POST' }, res, () => {});
});

app.post('/api/admin/withdraw-coins', async (req, res) => {
  const username = String(req.body?.username || '').trim();
  const amount = req.body?.amount;
  const walletType = String(req.body?.walletType || 'deposit').trim().toLowerCase();
  const user = await getUserByUsername(username);
  if (!user || user.is_admin === true) return res.status(404).json({ error: 'User not found' });
  req.body = { userId: Number(user.id), amount, walletType };
  return app._router.handle({ ...req, url: '/api/admin/withdraw-coin', method: 'POST' }, res, () => {});
});

app.post('/api/admin/toggle-block-user', async (req, res) => {
  const username = String(req.body?.username || '').trim();
  const user = await getUserByUsername(username);
  if (!user || user.is_admin === true) return res.status(404).json({ error: 'User not found' });
  req.body = { userId: Number(user.id) };
  return app._router.handle({ ...req, url: '/api/admin/block-user', method: 'POST' }, res, () => {});
});

app.get('/api/admin/transactions', (req, res) => app._router.handle({ ...req, url: '/api/admin/transaction-history', method: 'GET' }, res, () => {}));
app.post('/api/admin/settle', (req, res) => app._router.handle({ ...req, url: '/api/admin/force-settle-round', method: 'POST' }, res, () => {}));

app.get('/api/admin/export/dashboard.csv', adminOnly, requireAdminRoles('super_admin', 'finance_admin', 'game_admin', 'support_admin', 'read_only'), async (req, res) => {
  try {
    const range = getAdminRangeFromQuery(req.query || {});
    const [usersCount, pendingDep, pendingWit, activeUsers, totalDep, totalWit, betsCurrent, winsCurrent, betsPrevious, topDepositor, topWinner] = await Promise.all([
      pool.query(`SELECT COUNT(*)::int AS count FROM users WHERE is_admin = false`),
      pool.query(`SELECT COUNT(*)::int AS count FROM deposit_requests WHERE status = 'pending'`),
      pool.query(`SELECT COUNT(*)::int AS count FROM withdraw_requests WHERE status = 'pending'`),
      pool.query(`SELECT COUNT(DISTINCT id)::int AS count FROM users WHERE is_admin = false AND COALESCE(last_active_at,0) BETWEEN $1 AND $2`, [range.from, range.to]),
      pool.query(`SELECT COALESCE(SUM(amount),0) AS total FROM transactions WHERE type = 'deposit_approved' AND created_at BETWEEN $1 AND $2`, [range.from, range.to]),
      pool.query(`SELECT COALESCE(SUM(ABS(amount)),0) AS total FROM transactions WHERE type = 'withdrawal_approved' AND created_at BETWEEN $1 AND $2`, [range.from, range.to]),
      pool.query(`SELECT COUNT(*)::int AS count FROM bets WHERE created_at BETWEEN $1 AND $2`, [range.from, range.to]),
      pool.query(`SELECT COUNT(*)::int AS count FROM bets WHERE created_at BETWEEN $1 AND $2 AND result = 'win'`, [range.from, range.to]),
      pool.query(`SELECT COUNT(*)::int AS count FROM bets WHERE created_at BETWEEN $1 AND $2`, [range.previousFrom, range.previousTo]),
      pool.query(`SELECT u.username, COALESCE(SUM(t.amount),0) AS total FROM transactions t JOIN users u ON u.id=t.user_id WHERE t.type='deposit_approved' AND u.is_admin=false AND t.created_at BETWEEN $1 AND $2 GROUP BY u.username ORDER BY total DESC, u.username ASC LIMIT 1`, [range.from, range.to]),
      pool.query(`SELECT u.username, COALESCE(SUM(t.amount),0) AS total FROM transactions t JOIN users u ON u.id=t.user_id WHERE t.type='win_credit' AND u.is_admin=false AND t.created_at BETWEEN $1 AND $2 GROUP BY u.username ORDER BY total DESC, u.username ASC LIMIT 1`, [range.from, range.to])
    ]);
    const totalDeposits = Number(totalDep.rows[0]?.total || 0);
    const totalWithdrawals = Number(totalWit.rows[0]?.total || 0);
    return sendCsv(res, 'dashboard_export.csv', [{ preset: range.preset, from: new Date(range.from).toISOString(), to: new Date(range.to).toISOString(), topDepositor: topDepositor.rows[0]?.username || '-', totalDeposits, totalWithdrawals, profitLoss: totalDeposits - totalWithdrawals, topWinner: topWinner.rows[0]?.username || '-', todayVsYesterdayCurrent: Number(betsCurrent.rows[0]?.count || 0), todayVsYesterdayPrevious: Number(betsPrevious.rows[0]?.count || 0), activeUsers24h: Number(activeUsers.rows[0]?.count || 0), totalBetsToday: Number(betsCurrent.rows[0]?.count || 0), totalWinsToday: Number(winsCurrent.rows[0]?.count || 0), totalUsers: Number(usersCount.rows[0]?.count || 0), pendingRequests: Number(pendingDep.rows[0]?.count || 0) + Number(pendingWit.rows[0]?.count || 0) }]);
  } catch (error) {
    console.error('DASHBOARD EXPORT ERROR:', error);
    return res.status(500).json({ error: 'Unable to export dashboard CSV' });
  }
});

app.get('/api/admin/export/transactions.csv', adminOnly, requireAdminRoles('super_admin', 'finance_admin', 'support_admin', 'read_only', 'game_admin'), async (req, res) => {
  try {
    const range = getAdminRangeFromQuery(req.query || {});
    const walletType = String(req.query?.walletType || '').trim().toLowerCase();
    const result = await pool.query(`SELECT * FROM transactions WHERE type IN ('admin_add_coin', 'admin_withdraw_coin') AND COALESCE(meta->>'adminId', '') = $1 AND created_at BETWEEN $2 AND $3 AND ($4 = '' OR LOWER(COALESCE(meta->>'walletType','')) = $4) ORDER BY created_at DESC LIMIT 1000`, [String(req.user.id), range.from, range.to, walletType]);
    const rows = [];
    for (const item of result.rows) {
      const targetUser = await getUser(item.user_id);
      const meta = toJson(item.meta, {});
      rows.push({ id: Number(item.id), username: targetUser?.username || 'Deleted User', type: item.type, amount: Number(item.amount || 0), walletType: meta.walletType || '', createdAt: new Date(Number(item.created_at || 0)).toISOString() });
    }
    return sendCsv(res, 'transactions_export.csv', rows.length ? rows : [{ message: 'No rows' }]);
  } catch (error) {
    console.error('TRANSACTION EXPORT ERROR:', error);
    return res.status(500).json({ error: 'Unable to export transactions CSV' });
  }
});

app.get('/api/admin/export/requests.csv', adminOnly, requireAdminRoles('super_admin', 'finance_admin', 'read_only'), async (req, res) => {
  try {
    const range = getAdminRangeFromQuery(req.query || {});
    const statusFilter = String(req.query?.status || '').trim().toLowerCase();
    const depositResult = await pool.query(`SELECT * FROM deposit_requests WHERE created_at BETWEEN $1 AND $2 AND ($3 = '' OR LOWER(status) = $3)`, [range.from, range.to, statusFilter]);
    const withdrawResult = await pool.query(`SELECT * FROM withdraw_requests WHERE created_at BETWEEN $1 AND $2 AND ($3 = '' OR LOWER(status) = $3)`, [range.from, range.to, statusFilter]);
    const rows = [...depositResult.rows.map(item => ({ type: 'deposit', id: Number(item.id), username: item.username, amount: Number(item.amount || 0), method: item.method || '', status: item.status || '', createdAt: new Date(Number(item.created_at || 0)).toISOString() })), ...withdrawResult.rows.map(item => ({ type: 'withdrawal', id: Number(item.id), username: item.username, amount: Number(item.amount || 0), method: item.method || '', status: item.status || '', createdAt: new Date(Number(item.created_at || 0)).toISOString() }))].sort((a, b) => (a.createdAt < b.createdAt ? 1 : -1));
    return sendCsv(res, 'requests_export.csv', rows.length ? rows : [{ message: 'No rows' }]);
  } catch (error) {
    console.error('REQUEST EXPORT ERROR:', error);
    return res.status(500).json({ error: 'Unable to export requests CSV' });
  }
});

app.get('*', (req, res) => {
  return res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

(async () => {
  await testDB();
  await initDatabase();
  await ensureUsersSeeded();
  await ensureLiveUpdatesSeeded();
  await ensureActiveRound();

  app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
  });
})();
