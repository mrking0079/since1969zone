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
  ssl: {
    rejectUnauthorized: false
  }
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
const BONUS_AMOUNT = 50;
const BONUS_COOLDOWN_MS = 24 * 60 * 60 * 1000;
const PAYOUT_MULTIPLIER = 8;
const DEMO_USER_ID = 1;
const DATA_FILE = path.join(__dirname, 'data.json');
const DELETED_USERS_FILE = path.join(__dirname, 'deleted-users.json');

app.use(helmet({
  contentSecurityPolicy: false
}));
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

function nowMs() {
  return Date.now();
}

function sha256(value) {
  return crypto.createHash('sha256').update(value).digest('hex');
}

function randomHex(size = 32) {
  return crypto.randomBytes(size).toString('hex');
}

function hashPassword(password) {
  return sha256(`secure-live-game-password:${String(password || '')}`);
}

function isPasswordMatch(user, plainPassword) {
  const entered = String(plainPassword || '');
  const stored = String(user?.password || '');

  if (!stored) {
    return false;
  }

  // New hashed password format
  if (stored.startsWith('sha256$')) {
    return stored === `sha256$${hashPassword(entered)}`;
  }

  // Fallback for old plain-text users
  return stored === entered;
}

function jsonParseSafe(value, fallback) {
  try {
    return JSON.parse(value);
  } catch {
    return fallback;
  }
}

function createDefaultData() {
  return {
    users: [
      {
        id: 999,
        username: 'admin',
        password: `sha256$${hashPassword('admin123')}`,
        session_token: '',
        wallet_balance: 0,
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
        wallet_balance: 1000,
        total_played: 0,
        total_wins: 0,
        bonus_claimed: 0,
        last_bonus_time: 0,
        blocked: false,
        is_admin: false,
        created_at: nowMs()
      }
    ],
    rounds: [],
        bets: [],
    deposit_requests: [],
    withdraw_requests: [],
    transactions: [],
    live_updates: {
      paymentMethod: {
        upiId: '',
        qrCodeImage: '',
        bankAccount: ''
      },
      offer: ''
    },
    counters: {
      roundId: 1,
      betId: 1,
      transactionId: 1,
      depositRequestId: 1,
      withdrawRequestId: 1
    }
  };
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
  try {
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
        created_at BIGINT NOT NULL
      );
    `);

    await pool.query(`
      CREATE TABLE IF NOT EXISTS rounds (
        id BIGSERIAL PRIMARY KEY,
        round_number BIGINT NOT NULL,
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
    `);

    await pool.query(`
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
    `);

    await pool.query(`
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
    `);

    await pool.query(`
      CREATE TABLE IF NOT EXISTS withdraw_requests (
        id BIGSERIAL PRIMARY KEY,
        user_id BIGINT NOT NULL,
        username TEXT NOT NULL,
        amount NUMERIC NOT NULL,
        method TEXT DEFAULT '',
        details JSONB DEFAULT '{}'::jsonb,
        status TEXT DEFAULT 'pending',
        archived BOOLEAN DEFAULT FALSE,
        created_at BIGINT NOT NULL,
        updated_at BIGINT
      );
    `);

    await pool.query(`
      CREATE TABLE IF NOT EXISTS transactions (
        id BIGSERIAL PRIMARY KEY,
        user_id BIGINT NOT NULL,
        type TEXT NOT NULL,
        amount NUMERIC NOT NULL,
        meta JSONB DEFAULT '{}'::jsonb,
        created_at BIGINT NOT NULL
      );
    `);

    await pool.query(`
      CREATE TABLE IF NOT EXISTS live_updates (
        id BIGSERIAL PRIMARY KEY,
        payment_method JSONB DEFAULT '{}'::jsonb,
        offer TEXT DEFAULT ''
      );
    `);

    console.log('DB Tables Ready');
  } catch (err) {
    console.error('DB Init Error:', err);
  }
}

function loadData() {
  if (!fs.existsSync(DATA_FILE)) {
    const defaultData = createDefaultData();
    fs.writeFileSync(DATA_FILE, JSON.stringify(defaultData, null, 2), 'utf8');
    return defaultData;
  }

  try {
    const raw = fs.readFileSync(DATA_FILE, 'utf8');
    return jsonParseSafe(raw, createDefaultData());
  } catch {
    return createDefaultData();
  }
}

function saveData(data) {
  fs.writeFileSync(DATA_FILE, JSON.stringify(data, null, 2), 'utf8');
}

function loadDeletedUsersData() {
  if (!fs.existsSync(DELETED_USERS_FILE)) {
    fs.writeFileSync(DELETED_USERS_FILE, JSON.stringify({ deletedUsers: [] }, null, 2), 'utf8');
    return { deletedUsers: [] };
  }

  try {
    const raw = fs.readFileSync(DELETED_USERS_FILE, 'utf8');
    const parsed = jsonParseSafe(raw, { deletedUsers: [] });

    if (!Array.isArray(parsed.deletedUsers)) {
      parsed.deletedUsers = [];
    }

    return parsed;
  } catch {
    return { deletedUsers: [] };
  }
}

function saveDeletedUsersData(data) {
  fs.writeFileSync(DELETED_USERS_FILE, JSON.stringify(data, null, 2), 'utf8');
}

let db = loadData();

if (!Array.isArray(db.users)) {
  db.users = [];
}

db.users = db.users.map(user => {
  const normalizedUser = {
    blocked: false,
    is_admin: false,
    ...user
  };

  if (typeof normalizedUser.password === 'string' && normalizedUser.password && !normalizedUser.password.startsWith('sha256$')) {
    normalizedUser.password = `sha256$${hashPassword(normalizedUser.password)}`;
  }

  return normalizedUser;
});

if (!Array.isArray(db.deposit_requests)) {
  db.deposit_requests = [];
}

if (!Array.isArray(db.transactions)) {
  db.transactions = [];
}

if (!Array.isArray(db.rounds)) {
  db.rounds = [];
}

if (!Array.isArray(db.withdraw_requests)) {
  db.withdraw_requests = [];
}

if (!Array.isArray(db.bets)) {
  db.bets = [];
}

if (!db.live_updates) {
  db.live_updates = {};
}

if (!db.live_updates.paymentMethod) {
  db.live_updates.paymentMethod = {};
}

if (typeof db.live_updates.paymentMethod.upiId !== 'string') {
  db.live_updates.paymentMethod.upiId = '';
}

if (typeof db.live_updates.paymentMethod.qrCodeImage !== 'string') {
  db.live_updates.paymentMethod.qrCodeImage = '';
}

if (typeof db.live_updates.paymentMethod.bankAccount !== 'string') {
  db.live_updates.paymentMethod.bankAccount = '';
}

if (typeof db.live_updates.offer !== 'string') {
  db.live_updates.offer = '';
}

if (!db.counters) {
  db.counters = {};
}

if (typeof db.counters.roundId !== 'number') {
  db.counters.roundId = 1;
}

if (typeof db.counters.betId !== 'number') {
  db.counters.betId = 1;
}

if (typeof db.counters.transactionId !== 'number') {
  db.counters.transactionId = 1;
}

if (typeof db.counters.depositRequestId !== 'number') {
  db.counters.depositRequestId = 1;
}

if (typeof db.counters.withdrawRequestId !== 'number') {
  db.counters.withdrawRequestId = 1;
}

const existingAdmin = db.users.find(
  u => String(u.username || '').toLowerCase() === 'admin'
);

if (existingAdmin) {
  existingAdmin.is_admin = true;

  if (typeof existingAdmin.blocked !== 'boolean') {
    existingAdmin.blocked = false;
  }

  if (typeof existingAdmin.password === 'string' && !existingAdmin.password.startsWith('sha256$')) {
    existingAdmin.password = `sha256$${hashPassword(existingAdmin.password)}`;
  }
}

const hasAnyAdmin = db.users.some(u => u.is_admin === true);

if (!hasAnyAdmin) {
  db.users.unshift({
    id: 999,
    username: 'admin',
    password: `sha256$${hashPassword('admin123')}`,
    session_token: '',
    wallet_balance: 0,
    total_played: 0,
    total_wins: 0,
    bonus_claimed: 0,
    last_bonus_time: 0,
    blocked: false,
    is_admin: true,
    created_at: nowMs()
  });
}

saveData(db);

async function getUser(userId) {
  const result = await pool.query(
    `SELECT * FROM users WHERE id = $1 LIMIT 1`,
    [userId]
  );

  return result.rows[0] || null;
}

async function getUserByUsername(username) {
  const result = await pool.query(
    `SELECT * FROM users WHERE LOWER(username) = LOWER($1) LIMIT 1`,
    [String(username || '').trim()]
  );

  return result.rows[0] || null;
}

async function getUserBySessionToken(token) {
  const result = await pool.query(
    `SELECT * FROM users WHERE session_token = $1 LIMIT 1`,
    [String(token || '').trim()]
  );

  return result.rows[0] || null;
}

async function updateUserSessionToken(userId, sessionToken) {
  await pool.query(
    `UPDATE users SET session_token = $1 WHERE id = $2`,
    [sessionToken, userId]
  );
}

async function createUserRecord({ username, password, walletBalance = 1000, isAdmin = false }) {
  const createdAt = nowMs();

  const result = await pool.query(
    `INSERT INTO users (
      username,
      password,
      session_token,
      wallet_balance,
      total_played,
      total_wins,
      bonus_claimed,
      last_bonus_time,
      blocked,
      is_admin,
      created_at
    )
    VALUES ($1,$2,$3,$4,0,0,0,0,false,$5,$6)
    RETURNING *`,
    [
      username,
      password,
      crypto.randomUUID(),
      walletBalance,
      isAdmin,
      createdAt
    ]
  );

  return result.rows[0];
}

async function updateUserWalletAndStats(userId, fields = {}) {
  const updates = [];
  const values = [];
  let index = 1;

  for (const [key, value] of Object.entries(fields)) {
    updates.push(`${key} = $${index++}`);
    values.push(value);
  }

  if (!updates.length) return;

  values.push(userId);

  await pool.query(
    `UPDATE users SET ${updates.join(', ')} WHERE id = $${index}`,
    values
  );
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

  await pool.query(
    `UPDATE users SET ${updates.join(', ')} WHERE id = $${index}`,
    values
  );
}

async function setUserBlockedStatus(userId, blocked) {
  await pool.query(
    `UPDATE users SET blocked = $1 WHERE id = $2`,
    [Boolean(blocked), userId]
  );
}

async function deleteUserById(userId) {
  await pool.query(
    `DELETE FROM users WHERE id = $1`,
    [userId]
  );
}

async function ensureUsersSeeded() {
  for (const user of db.users || []) {
    const username = String(user.username || '').trim();
    if (!username) continue;

    await pool.query(
      `INSERT INTO users (
        id,
        username,
        password,
        session_token,
        wallet_balance,
        total_played,
        total_wins,
        bonus_claimed,
        last_bonus_time,
        blocked,
        is_admin,
        created_at
      ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)
      ON CONFLICT (username) DO NOTHING`,
      [
        Number(user.id),
        username,
        String(user.password || ''),
        String(user.session_token || ''),
        Number(user.wallet_balance || 0),
        Number(user.total_played || 0),
        Number(user.total_wins || 0),
        Number(user.bonus_claimed || 0),
        Number(user.last_bonus_time || 0),
        Boolean(user.blocked),
        Boolean(user.is_admin),
        Number(user.created_at || nowMs())
      ]
    );
  }
}

async function getUserIdFromReq(req) {
  const token = String(req.header('x-auth-token') || '').trim();

  if (!token) {
    return null;
  }

  const user = await getUserBySessionToken(token);
  if (!user) {
    return null;
  }

  return Number(user.id);
}

async function adminOnly(req, res, next) {
  try {
    const userId = await getUserIdFromReq(req);

    if (!userId) {
      return res.status(401).json({ error: 'Login required' });
    }

    const user = await getUser(userId);

    if (!user) {
      return res.status(401).json({ error: 'User not found' });
    }

    if (user.is_admin !== true) {
      return res.status(403).json({ error: 'Admin access only' });
    }

    req.user = user;
    next();
  } catch (error) {
    return res.status(500).json({ error: 'Admin auth failed' });
  }
}

function getCurrentRound() {
  const active = db.rounds
    .filter(r => r.status === 'open' || r.status === 'closed')
    .sort((a, b) => b.round_number - a.round_number);
  return active[0] || null;
}

function getLastSettledRound() {
  const settled = db.rounds
    .filter(r => r.status === 'settled')
    .sort((a, b) => b.round_number - a.round_number);
  return settled[0] || null;
}

function getLast10SettledRounds() {
  return db.rounds
    .filter(r => r.status === 'settled' && r.lucky_number !== null && r.lucky_number !== undefined)
    .sort((a, b) => b.round_number - a.round_number)
    .slice(0, 10)
    .map(round => ({
      roundNumber: round.round_number,
      luckyNumber: round.lucky_number
    }));
}

function getBetForRound(userId, roundId) {
  return db.bets.find(b => b.user_id === userId && b.round_id === roundId) || null;
}

function getRecentHistory(userId = null, limit = 500) {
  const settledRounds = db.rounds
    .filter(r => r.status === 'settled')
    .sort((a, b) => b.round_number - a.round_number)
    .slice(0, limit);

  return settledRounds.map(round => {
    const userBet = userId
      ? db.bets.find(b => b.user_id === userId && b.round_id === round.id)
      : null;

    const betSummary = userBet
      ? Object.entries(userBet.bet_map || {})
          .map(([num, amt]) => `${num}:${amt}`)
          .join(', ')
      : '-';

    return {
      round_number: round.round_number,
      round_code: round.round_code || `${new Date(round.starts_at).getFullYear()}${String(new Date(round.starts_at).getMonth() + 1).padStart(2, '0')}${String(new Date(round.starts_at).getDate()).padStart(2, '0')}${String((((round.round_number || 1) - 1) % 50000) + 1).padStart(5, '0')}`,
      lucky_number: round.lucky_number,
      bet_map: userBet ? userBet.bet_map : {},
      bet_display: betSummary || '-',
      result: userBet ? userBet.result || '-' : '-',
      payout: userBet && Number(userBet.payout) !== 0 ? userBet.payout : '-',
      isWinner: userBet ? userBet.result === 'win' : false,
      total_coins: userBet ? userBet.total_coins : 0,
      hasBet: Boolean(userBet)
    };
  });
}

function createRound(roundNumber, startsAt) {
  const bettingClosesAt = startsAt + (ROUND_SECONDS - BETTING_CLOSE_SECONDS) * 1000;
  const endsAt = startsAt + ROUND_SECONDS * 1000;
  const serverSeed = randomHex(32);
  const clientSeed = `round-${roundNumber}-public-demo-seed`;
  const serverSeedHash = sha256(serverSeed);

  const dateObj = new Date(startsAt);
  const year = String(dateObj.getFullYear());
  const month = String(dateObj.getMonth() + 1).padStart(2, '0');
  const day = String(dateObj.getDate()).padStart(2, '0');
  const datePart = `${year}${month}${day}`;

  const displayRoundNumber = ((roundNumber - 1) % 50000) + 1;
  const roundCode = `${datePart}${String(displayRoundNumber).padStart(5, '0')}`;

  const round = {
    id: db.counters.roundId++,
    round_number: roundNumber,
    round_code: roundCode,
    starts_at: startsAt,
    betting_closes_at: bettingClosesAt,
    ends_at: endsAt,
    status: 'open',
    server_seed: serverSeed,
    server_seed_hash: serverSeedHash,
    client_seed: clientSeed,
    lucky_number: null,
    settled_at: null,
    created_at: nowMs()
  };

  db.rounds.push(round);
  saveData(db);
  return round;
}

function computeLuckyNumber(serverSeed, clientSeed, roundNumber) {
  const digest = sha256(`${serverSeed}:${clientSeed}:${roundNumber}`);
  const value = parseInt(digest.slice(0, 8), 16);
  return value % 10;
}

function getStatusForRound(round) {
  const now = nowMs();
  if (!round) return 'waiting';
  if (now < round.betting_closes_at) return 'open';
  if (now < round.ends_at) return 'closed';
  return 'awaiting_settlement';
}
async function settleRoundTx(roundId) {
  const round = db.rounds.find(r => r.id === roundId);
  if (!round) throw new Error('Round not found');
  if (round.status === 'settled') throw new Error('Round already settled');
  if (nowMs() < round.ends_at) throw new Error('Round timer not finished yet');

  const luckyNumber = computeLuckyNumber(round.server_seed, round.client_seed, round.round_number);

  round.status = 'settled';
  round.lucky_number = luckyNumber;
  round.settled_at = nowMs();

  const bets = db.bets.filter(b => b.round_id === round.id);

  for (const bet of bets) {
    const matchedAmount = Number(bet.bet_map[String(luckyNumber)] || 0);
    const payout = matchedAmount > 0 ? matchedAmount * PAYOUT_MULTIPLIER : 0;
    const result = payout > 0 ? 'win' : 'lose';

    bet.matched_number = luckyNumber;
    bet.payout = payout;
    bet.result = result;

    if (payout > 0) {
      const user = await getUser(bet.user_id);
      if (user) {
        await incrementUserFields(bet.user_id, {
          wallet_balance: payout,
          total_wins: 1
        });
      }

      addTransaction(bet.user_id, 'win_credit', payout, {
        roundId: round.id,
        luckyNumber
      });
    }
  }

  saveData(db);
}

async function ensureActiveRound() {
  const latest = [...db.rounds].sort((a, b) => b.round_number - a.round_number)[0];
  const now = nowMs();

  if (!latest) {
    return createRound(1, now);
  }

  if (latest.status !== 'settled') {
    if (latest.status === 'open' && now >= latest.betting_closes_at) {
      latest.status = 'closed';
      saveData(db);
    }

    if (now >= latest.ends_at) {
      await settleRoundTx(latest.id);
      return createRound(latest.round_number + 1, nowMs());
    }

    return latest;
  }

  return createRound(latest.round_number + 1, now);
}

async function createNextRoundIfNeeded() {
  return await ensureActiveRound();
}

async function syncRoundState() {
  return await ensureActiveRound();
}

async function buildGameState(userId = DEMO_USER_ID) {
  const round = await syncRoundState();
  const user = await getUser(userId);

  if (!user) {
    return {
      user: {
        id: null,
        username: 'Guest',
        walletBalance: 0,
        totalPlayed: 0,
        totalWins: 0,
        bonusClaimed: 0,
        lastBonusTime: null
      },
      round: round ? {
        id: round.id,
        roundNumber: round.round_number,
        startsAt: round.starts_at,
        bettingClosesAt: round.betting_closes_at,
        endsAt: round.ends_at,
        status: getStatusForRound(round),
        serverSeedHash: round.server_seed_hash,
        clientSeed: round.client_seed,
        alreadyPlaced: false
      } : null,
      placedBet: null,
      lastSettledRound: null,
      last10LuckyNumbers: getLast10SettledRounds(),
      history: []
    };
  }

  const placedBet = round ? getBetForRound(userId, round.id) : null;
  const lastSettled = getLastSettledRound();
  const history = getRecentHistory(userId);
  const depositRequests = (db.deposit_requests || []).filter(
    request => request.user_id === user.id
  );

    const withdrawRequests = (db.withdraw_requests || []).filter(
    request => request.user_id === user.id
  );

  return {
    user: {
      id: user.id,
      username: user.username,
      walletBalance: user.wallet_balance,
      totalPlayed: user.total_played,
      totalWins: user.total_wins,
      bonusClaimed: user.bonus_claimed,
      lastBonusTime: user.last_bonus_time
    },
    round: round ? {
      id: round.id,
      roundNumber: round.round_number,
      startsAt: round.starts_at,
      bettingClosesAt: round.betting_closes_at,
      endsAt: round.ends_at,
      status: getStatusForRound(round),
      serverSeedHash: round.server_seed_hash,
      clientSeed: round.client_seed,
      alreadyPlaced: Boolean(placedBet)
    } : null,
    placedBet: placedBet ? {
      totalCoins: placedBet.total_coins,
      betMap: placedBet.bet_map,
      result: placedBet.result,
      payout: placedBet.payout
    } : null,
    lastSettledRound: lastSettled ? {
      roundNumber: lastSettled.round_number,
      luckyNumber: lastSettled.lucky_number,
      serverSeedHash: lastSettled.server_seed_hash,
      serverSeed: lastSettled.server_seed,
      clientSeed: lastSettled.client_seed,
      settledAt: lastSettled.settled_at
    } : null,
    last10LuckyNumbers: getLast10SettledRounds(),
    history,
    depositRequests,
    withdrawRequests
  };
}

function validateBetMap(betMap) {
  if (!betMap || typeof betMap !== 'object' || Array.isArray(betMap)) {
    return { ok: false, error: 'Invalid bet map' };
  }

  const keys = Object.keys(betMap);
  if (keys.length === 0) {
    return { ok: false, error: 'Select at least one number' };
  }
  if (keys.length > 10) {
    return { ok: false, error: 'Too many selections' };
  }

  let total = 0;
  const sanitized = {};

  for (const key of keys) {
    if (!/^\d$/.test(key)) {
      return { ok: false, error: 'Only numbers 0 to 9 are allowed' };
    }
    const amount = Number(betMap[key]);
    if (!Number.isInteger(amount) || amount <= 0) {
      return { ok: false, error: 'Each bet amount must be a positive integer' };
    }
    if (amount > 10000) {
      return { ok: false, error: 'Single number amount limit is 10000' };
    }
    total += amount;
    sanitized[key] = amount;
  }

  if (total < 1) {
    return { ok: false, error: 'Minimum total bet is 1 coin' };
  }
  if (total > 50000) {
    return { ok: false, error: 'Maximum total bet is 50000 coins' };
  }

  return { ok: true, sanitized, total };
}

function addTransaction(userId, type, amount, meta = {}) {
  db.transactions.push({
    id: db.counters.transactionId++,
    user_id: userId,
    type,
    amount,
    meta,
    created_at: nowMs()
  });
}

async function placeBetTx(userId, roundId, betMap, totalCoins) {
  const user = await getUser(userId);
  if (!user) throw new Error('User not found');
  if (Number(user.wallet_balance || 0) < totalCoins) throw new Error('Insufficient wallet balance');

  const existingBet = getBetForRound(userId, roundId);
  if (existingBet) throw new Error('Bet already placed for this round');

  db.bets.push({
    id: db.counters.betId++,
    round_id: roundId,
    user_id: userId,
    bet_map: betMap,
    total_coins: totalCoins,
    matched_number: null,
    payout: 0,
    result: 'pending',
    created_at: nowMs()
  });

  await incrementUserFields(userId, {
    wallet_balance: -totalCoins,
    total_played: totalCoins
  });

  addTransaction(userId, 'bet_debit', -totalCoins, { roundId });
  saveData(db);
}

async function claimBonusTx(userId) {
  const user = await getUser(userId);
  if (!user) throw new Error('User not found');

  const current = nowMs();
  if (current - Number(user.last_bonus_time || 0) < BONUS_COOLDOWN_MS) {
    throw new Error('Bonus is not available yet');
  }

  await incrementUserFields(userId, {
    wallet_balance: BONUS_AMOUNT,
    bonus_claimed: 1
  });

  await updateUserWalletAndStats(userId, {
    last_bonus_time: current
  });

  addTransaction(userId, 'bonus_credit', BONUS_AMOUNT, {});
  saveData(db);
}

app.post('/api/login', async (req, res) => {
  try {
    const username = String(req.body?.username || '').trim();
    const password = String(req.body?.password || '').trim();

    if (!username) {
      return res.status(400).json({ error: 'Username required' });
    }

    if (!password) {
      return res.status(400).json({ error: 'Password required' });
    }

    const user = await getUserByUsername(username);

    if (!user) {
      return res.status(404).json({ error: 'Username does not exist. Please sign up first.' });
    }

    if (!isPasswordMatch(user, password)) {
      return res.status(401).json({ error: 'Wrong password' });
    }

    if (user.blocked) {
      return res.status(403).json({ error: 'Your account is blocked by admin' });
    }

    const newSessionToken = crypto.randomUUID();
    await updateUserSessionToken(user.id, newSessionToken);

    return res.json({
      success: true,
      user: {
        id: user.id,
        username: user.username,
        sessionToken: newSessionToken,
        walletBalance: Number(user.wallet_balance || 0),
        totalPlayed: Number(user.total_played || 0),
        totalWins: Number(user.total_wins || 0),
        bonusClaimed: Number(user.bonus_claimed || 0),
        lastBonusTime: Number(user.last_bonus_time || 0)
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

    if (!ADMIN_KEY || adminKey !== ADMIN_KEY) {
      return res.status(404).json({ error: 'Not found' });
    }

    if (!username) {
      return res.status(400).json({ error: 'Username required' });
    }

    if (!password) {
      return res.status(400).json({ error: 'Password required' });
    }

    const user = await getUserByUsername(username);

    if (!user || user.is_admin !== true) {
      return res.status(401).json({ error: 'Admin account not found' });
    }

    if (user.blocked) {
      return res.status(403).json({ error: 'Your account is blocked by admin' });
    }

    if (!isPasswordMatch(user, password)) {
      return res.status(401).json({ error: 'Invalid admin password' });
    }

    const newSessionToken = crypto.randomUUID();
    await updateUserSessionToken(user.id, newSessionToken);

    return res.json({
      success: true,
      user: {
        id: user.id,
        username: user.username,
        sessionToken: newSessionToken,
        walletBalance: Number(user.wallet_balance || 0),
        totalPlayed: Number(user.total_played || 0),
        totalWins: Number(user.total_wins || 0),
        bonusClaimed: Number(user.bonus_claimed || 0),
        lastBonusTime: Number(user.last_bonus_time || 0),
        isAdmin: true
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

    if (!username) {
      return res.status(400).json({ error: 'Username required' });
    }

    if (!password) {
      return res.status(400).json({ error: 'Password required' });
    }

    const existingUser = await getUserByUsername(username);

    if (existingUser) {
      return res.status(409).json({ error: 'Username already exists' });
    }

    const user = await createUserRecord({
      username,
      password: `sha256$${hashPassword(password)}`,
      walletBalance: 1000,
      isAdmin: false
    });

    return res.json({
      success: true,
      message: 'Signup successful',
      user: {
        id: user.id,
        username: user.username,
        sessionToken: user.session_token,
        walletBalance: Number(user.wallet_balance || 0),
        totalPlayed: Number(user.total_played || 0),
        totalWins: Number(user.total_wins || 0),
        bonusClaimed: Number(user.bonus_claimed || 0),
        lastBonusTime: Number(user.last_bonus_time || 0)
      }
    });
  } catch (error) {
    console.error('SIGNUP ERROR:', error);
    return res.status(500).json({ error: 'Signup failed' });
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
    if (status !== 'open') {
      return res.status(400).json({ error: 'Betting is closed for this round' });
    }

    const validation = validateBetMap(req.body?.betMap);
    if (!validation.ok) {
      return res.status(400).json({ error: validation.error });
    }

    await placeBetTx(userId, round.id, validation.sanitized, validation.total);
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

    await claimBonusTx(userId);
    return res.json({
      success: true,
      message: `Bonus claimed: +${BONUS_AMOUNT}`,
      state: await buildGameState(userId)
    });
  } catch (error) {
    return res.status(400).json({ error: error.message || 'Unable to claim bonus' });
  }
});

async function uploadDepositProofToCloudinary(base64Image, username) {
  const safeImage = String(base64Image || '').trim();

  if (!safeImage) {
    throw new Error('Screenshot image is missing');
  }

  if (!safeImage.startsWith('data:image/')) {
    throw new Error('Invalid screenshot image format');
  }

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

    if (!Number.isFinite(amount) || amount <= 0) {
      return res.status(400).json({ error: 'Valid deposit amount required' });
    }

    if (!method) {
      return res.status(400).json({ error: 'Payment method required' });
    }

    if (!utr && !screenshot) {
      return res.status(400).json({ error: 'Provide UTR or screenshot proof' });
    }

    if (!screenshot) {
      return res.status(400).json({ error: 'Screenshot proof required' });
    }

    const screenshotUrl = await uploadDepositProofToCloudinary(screenshot, user.username);

    const request = {
      id: db.counters.depositRequestId++,
      user_id: user.id,
      username: user.username,
      amount,
      method,
      utr,
      screenshot: screenshotUrl,
      status: 'pending',
      created_at: nowMs(),
      updated_at: null
    };

    db.deposit_requests.push(request);

    addTransaction(user.id, 'deposit_request', 0, {
     requestId: request.id,
     method,
     utr,
     screenshot: screenshotUrl
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

    if (!Number.isFinite(amount) || amount <= 0) {
      return res.status(400).json({ error: 'Valid withdraw amount required' });
    }

    if (!method) {
      return res.status(400).json({ error: 'Withdrawal method required' });
    }

    if (method === 'UPI' && !upiId) {
      return res.status(400).json({ error: 'UPI ID required' });
    }

    if (method === 'QR Code' && !String(details?.qrImage || '').trim()) {
      return res.status(400).json({ error: 'QR image required' });
    }

    if (method === 'Bank Account') {
      if (!String(details?.bankHolderName || '').trim()) {
        return res.status(400).json({ error: 'Bank holder name required' });
      }

      if (!String(details?.bankName || '').trim()) {
        return res.status(400).json({ error: 'Bank name required' });
      }

      if (!String(details?.ifscCode || '').trim()) {
        return res.status(400).json({ error: 'IFSC code required' });
      }

      if (!String(details?.accountNumber || '').trim()) {
        return res.status(400).json({ error: 'Account number required' });
      }
    }

    if (Number(user.wallet_balance || 0) < amount) {
      return res.status(400).json({ error: 'Insufficient wallet balance' });
    }

    const hasPendingRequest = (db.withdraw_requests || []).some(
      request => request.user_id === user.id && request.status === 'pending'
    );

    if (hasPendingRequest) {
      return res.status(400).json({ error: 'You already have a pending withdraw request' });
    }

    const request = {
      id: db.counters.withdrawRequestId++,
      user_id: user.id,
      username: user.username,
      amount,
      method,
      details,
      upiId,
      status: 'pending',
      created_at: nowMs(),
      updated_at: null
    };

    db.withdraw_requests.push(request);

    addTransaction(user.id, 'withdraw_request', 0, {
      requestId: request.id,
      method,
      upiId,
      details,
      amount
    });

    saveData(db);

    return res.json({
      success: true,
      message: 'Withdraw request submitted',
      state: await buildGameState(userId)
    });
  } catch (error) {
    return res.status(500).json({ error: error.message || 'Withdraw failed' });
  }
});

app.get('/api/live-updates', (req, res) => {
  const liveUpdates = db.live_updates || {
    paymentMethod: { upiId: '', qrCodeImage: '', bankAccount: '' },
    offer: ''
  };

  return res.json({
    success: true,
    liveUpdates
  });
});

app.get('/api/admin/live-updates', adminOnly, (req, res) => {
  const liveUpdates = db.live_updates || {
    paymentMethod: { upiId: '', qrCodeImage: '', bankAccount: '' },
    offer: ''
  };

  return res.json({
    success: true,
    liveUpdates
  });
});

app.post('/api/admin/live-updates', adminOnly, (req, res) => {
  try {
    const section = String(req.body?.section || '').trim();
    const type = String(req.body?.type || '').trim();

    if (!db.live_updates) {
      db.live_updates = {
        paymentMethod: { upiId: '', qrCodeImage: '', bankAccount: '' },
        offer: ''
      };
    }

    if (!db.live_updates.paymentMethod) {
      db.live_updates.paymentMethod = {
        upiId: '',
        qrCodeImage: '',
        bankAccount: ''
      };
    }

    if (section === 'payment-method') {
      if (type === 'upi-id') {
        db.live_updates.paymentMethod.upiId = String(req.body?.upiId || '').trim();
      }

      if (type === 'qr-code') {
        db.live_updates.paymentMethod.qrCodeImage = String(req.body?.qrCodeImage || '').trim();
      }

      if (type === 'bank-account') {
        db.live_updates.paymentMethod.bankAccount = String(req.body?.bankAccount || '').trim();
      }
    }

    if (section === 'offer') {
      db.live_updates.offer = String(req.body?.offer || '').trim();
    }

    saveData(db);

    return res.json({
      success: true,
      message: 'Live updates saved successfully',
      liveUpdates: db.live_updates
    });
  } catch (error) {
    return res.status(500).json({ error: 'Unable to save live updates' });
  }
});

app.get('/api/admin/load-users', adminOnly, async (req, res) => {
  const result = await pool.query(
    `SELECT id, username, wallet_balance, total_played, total_wins, bonus_claimed, blocked, created_at
     FROM users
     WHERE is_admin IS NOT TRUE
     ORDER BY id DESC`
  );

  const users = result.rows.map(user => ({
    id: Number(user.id),
    username: user.username,
    walletBalance: Number(user.wallet_balance || 0),
    totalPlayed: Number(user.total_played || 0),
    totalWins: Number(user.total_wins || 0),
    bonusClaimed: Number(user.bonus_claimed || 0),
    blocked: Boolean(user.blocked),
    createdAt: Number(user.created_at || 0)
  }));

  return res.json({ users });
});

app.post('/api/admin/add-coin', adminOnly, async (req, res) => {
  try {
    const userId = Number(req.body?.userId);
    const amount = Number(req.body?.amount);

    if (!Number.isInteger(userId) || userId <= 0) {
      return res.status(400).json({ error: 'Valid userId required' });
    }

    if (!Number.isFinite(amount) || amount <= 0) {
      return res.status(400).json({ error: 'Valid amount required' });
    }

    const user = await getUser(userId);
    if (!user || user.is_admin === true) {
      return res.status(404).json({ error: 'User not found' });
    }

    await incrementUserFields(user.id, {
      wallet_balance: amount
    });
    addTransaction(user.id, 'admin_add_coin', amount, { adminId: req.user.id });
    saveData(db);

    return res.json({
      success: true,
      message: `${amount} coins added to ${user.username}`,
      user: {
        id: user.id,
        username: user.username,
        walletBalance: Number(user.wallet_balance || 0) + amount
      }
    });
  } catch (error) {
    return res.status(500).json({ error: 'Unable to add coins' });
  }
});

app.post('/api/admin/withdraw-coin', adminOnly, async (req, res) => {
  try {
    const userId = Number(req.body?.userId);
    const amount = Number(req.body?.amount);

    if (!Number.isInteger(userId) || userId <= 0) {
      return res.status(400).json({ error: 'Valid userId required' });
    }

    if (!Number.isFinite(amount) || amount <= 0) {
      return res.status(400).json({ error: 'Valid amount required' });
    }

    const user = await getUser(userId);
    if (!user || user.is_admin === true) {
      return res.status(404).json({ error: 'User not found' });
    }

    if (Number(user.wallet_balance || 0) < amount) {
      return res.status(400).json({ error: 'User has insufficient balance' });
    }

    await incrementUserFields(user.id, {
      wallet_balance: -amount
    });
    addTransaction(user.id, 'admin_withdraw_coin', -amount, { adminId: req.user.id });
    saveData(db);

    return res.json({
      success: true,
      message: `${amount} coins removed from ${user.username}`,
      user: {
        id: user.id,
        username: user.username,
        walletBalance: Number(user.wallet_balance || 0) - amount
      }
    });
  } catch (error) {
    return res.status(500).json({ error: 'Unable to withdraw coins' });
  }
});

app.post('/api/admin/block-user', adminOnly, async (req, res) => {
  try {
    const userId = Number(req.body?.userId);

    if (!Number.isInteger(userId) || userId <= 0) {
      return res.status(400).json({ error: 'Valid userId required' });
    }

    const user = await getUser(userId);
    if (!user || user.is_admin === true) {
      return res.status(404).json({ error: 'User not found' });
    }

    const nextBlocked = !user.blocked;
    await setUserBlockedStatus(user.id, nextBlocked);
    saveData(db);

    return res.json({
      success: true,
      message: nextBlocked ? `${user.username} blocked` : `${user.username} unblocked`,
      blocked: nextBlocked
    });
  } catch (error) {
    return res.status(500).json({ error: 'Unable to update block status' });
  }
});

app.post('/api/admin/delete-user', adminOnly, async (req, res) => {
  try {
    const userId = Number(req.body?.userId);

    if (!Number.isInteger(userId) || userId <= 0) {
      return res.status(400).json({ error: 'Valid userId required' });
    }

    const user = await getUser(userId);
    if (!user || user.is_admin === true) {
      return res.status(404).json({ error: 'User not found' });
    }

    const deletedUsersData = loadDeletedUsersData();
    deletedUsersData.deletedUsers.push({
      ...user,
      deleted_at: nowMs()
    });
    saveDeletedUsersData(deletedUsersData);

    await deleteUserById(userId);

    db.bets = db.bets.filter(b => b.user_id !== userId);
    db.transactions = db.transactions.filter(t => t.user_id !== userId);
    db.deposit_requests = db.deposit_requests.filter(r => r.user_id !== userId);
    db.withdraw_requests = db.withdraw_requests.filter(r => r.user_id !== userId);

    saveData(db);

    return res.json({
      success: true,
      message: `${user.username} deleted successfully`
    });
  } catch (error) {
    return res.status(500).json({ error: 'Unable to delete user' });
  }
});

app.get('/api/admin/transaction-history', adminOnly, async (req, res) => {
  const userRows = await pool.query(`SELECT id, username FROM users`);
  const userMap = new Map(userRows.rows.map(row => [Number(row.id), row.username]));

  const history = [...db.transactions]
    .sort((a, b) => b.created_at - a.created_at)
    .slice(0, 1000)
    .map(item => ({
      id: item.id,
      userId: item.user_id,
      username: userMap.get(Number(item.user_id)) || 'Deleted User',
      type: item.type,
      amount: item.amount,
      meta: item.meta || {},
      createdAt: item.created_at
    }));

  return res.json({ history });
});

app.get('/api/admin/deposit-requests', adminOnly, (req, res) => {
  const depositRequests = [...(db.deposit_requests || [])].map(item => ({
    id: item.id,
    type: 'deposit',
    userId: item.user_id,
    username: item.username,
    amount: item.amount,
    method: item.method || '',
    utr: item.utr || '',
    screenshot: item.screenshot || '',
    status: item.status,
    createdAt: item.created_at,
    updatedAt: item.updated_at || null
  }));

  const withdrawalRequests = [...(db.withdraw_requests || [])].map(item => ({
    id: item.id,
    type: 'withdrawal',
    userId: item.user_id,
    username: item.username,
    amount: item.amount,
    method: item.method || '',
    withdrawal_details: item.details || {},
    upiId: item.upiId || '',
    status: item.status,
    createdAt: item.created_at,
    updatedAt: item.updated_at || null
  }));

  const requests = [...depositRequests, ...withdrawalRequests]
    .sort((a, b) => (b.createdAt || 0) - (a.createdAt || 0));

  return res.json({ requests });
});

app.post('/api/admin/deposit-requests/action', adminOnly, async (req, res) => {
  try {
    const requestId = Number(req.body?.requestId);
    const action = String(req.body?.action || '').trim().toLowerCase();
    const type = String(req.body?.type || '').trim().toLowerCase();

    if (!Number.isInteger(requestId) || requestId <= 0) {
      return res.status(400).json({ error: 'Valid requestId required' });
    }

    if (!['approve', 'reject'].includes(action)) {
      return res.status(400).json({ error: 'Valid action required' });
    }

    if (!['deposit', 'withdrawal'].includes(type)) {
      return res.status(400).json({ error: 'Valid request type required' });
    }

    if (type === 'deposit') {
      const request = db.deposit_requests.find(r => r.id === requestId);
      if (!request) {
        return res.status(404).json({ error: 'Deposit request not found' });
      }

      if (request.status !== 'pending') {
        return res.status(400).json({ error: 'This deposit request is already processed' });
      }

      const user = await getUser(request.user_id);
      if (!user) {
        return res.status(404).json({ error: 'User not found' });
      }

      request.status = action === 'approve' ? 'approved' : 'rejected';
      request.updated_at = nowMs();

      if (action === 'approve') {
        await incrementUserFields(user.id, {
          wallet_balance: Number(request.amount || 0)
        });
        addTransaction(user.id, 'deposit_approved', Number(request.amount || 0), {
          requestId: request.id,
          adminId: req.user.id
        });
      }

      saveData(db);

      return res.json({
        success: true,
        message: action === 'approve'
          ? 'Deposit request approved successfully'
          : 'Deposit request rejected successfully',
        request
      });
    }

    if (type === 'withdrawal') {
      const request = db.withdraw_requests.find(r => r.id === requestId);
      if (!request) {
        return res.status(404).json({ error: 'Withdrawal request not found' });
      }

      if (request.status !== 'pending') {
        return res.status(400).json({ error: 'This withdrawal request is already processed' });
      }

      const user = await getUser(request.user_id);
      if (!user) {
        return res.status(404).json({ error: 'User not found' });
      }

      if (action === 'approve' && Number(user.wallet_balance || 0) < Number(request.amount || 0)) {
        return res.status(400).json({ error: 'User has insufficient wallet balance for approval' });
      }

      request.status = action === 'approve' ? 'approved' : 'rejected';
      request.updated_at = nowMs();

      if (action === 'approve') {
        await incrementUserFields(user.id, {
          wallet_balance: -Number(request.amount || 0)
        });
        addTransaction(user.id, 'withdrawal_approved', -Number(request.amount || 0), {
          requestId: request.id,
          adminId: req.user.id,
          method: request.method || '',
          upiId: request.upiId || '',
          details: request.details || {}
        });
      }

      if (action === 'reject') {
        addTransaction(user.id, 'withdraw_rejected', 0, {
          requestId: request.id,
          adminId: req.user.id,
          method: request.method || '',
          upiId: request.upiId || '',
          details: request.details || {}
        });
      }

      saveData(db);

      return res.json({
        success: true,
        message: action === 'approve'
          ? 'Withdrawal request approved successfully'
          : 'Withdrawal request rejected successfully',
        request
      });
    }

    return res.status(400).json({ error: 'Invalid request type' });
  } catch (error) {
    return res.status(500).json({ error: 'Unable to update request' });
  }
});

app.get('/api/admin/dashboard-stats', adminOnly, (req, res) => {
  try {
    const approvedDeposits = db.transactions
      .filter(tx => tx.type === 'deposit_approved')
      .reduce((sum, tx) => sum + Number(tx.amount || 0), 0);

    const approvedWithdrawals = Math.abs(
      db.transactions
        .filter(tx => tx.type === 'withdrawal_approved')
        .reduce((sum, tx) => sum + Number(tx.amount || 0), 0)
    );

    return res.json({
      stats: {
        totalDeposits: approvedDeposits,
        totalWithdrawals: approvedWithdrawals,
        profitLoss: approvedDeposits - approvedWithdrawals
      }
    });
  } catch (error) {
    return res.status(500).json({ error: 'Unable to load dashboard stats' });
  }
});

app.get('/api/admin/current-round', adminOnly, async (req, res) => {
  try {
    const round = await syncRoundState();
    if (!round) {
      return res.status(404).json({ error: 'No active round found' });
    }

    const relatedBets = db.bets.filter(b => b.round_id === round.id);

    return res.json({
      round: {
        id: round.id,
        roundNumber: round.round_number,
        roundCode: round.round_code || '-',
        status: getStatusForRound(round),
        startsAt: round.starts_at,
        bettingClosesAt: round.betting_closes_at,
        endsAt: round.ends_at,
        serverSeedHash: round.server_seed_hash,
        clientSeed: round.client_seed,
        totalBets: relatedBets.length,
        totalCoins: relatedBets.reduce((sum, bet) => sum + Number(bet.total_coins || 0), 0)
      }
    });
  } catch (error) {
    return res.status(500).json({ error: 'Unable to load current round' });
  }
});

app.post('/api/admin/force-settle-round', adminOnly, async (req, res) => {
  try {
    const round = getCurrentRound();
    if (!round) {
      return res.status(404).json({ error: 'No active round found' });
    }

    round.ends_at = Math.min(round.ends_at, nowMs());
    await settleRoundTx(round.id);
    await createNextRoundIfNeeded();

    return res.json({
      success: true,
      message: 'Round settled successfully'
    });
  } catch (error) {
    return res.status(400).json({ error: error.message || 'Unable to settle round' });
  }
});

app.get('/api/admin/user-history/:username', adminOnly, async (req, res) => {
  try {
    const username = String(req.params.username || '').trim();
    if (!username) {
      return res.status(400).json({ error: 'Username required' });
    }

    const user = await getUserByUsername(username);

    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }

    const bets = db.bets
      .filter(b => b.user_id === Number(user.id))
      .sort((a, b) => b.created_at - a.created_at)
      .map(bet => {
        const round = db.rounds.find(r => r.id === bet.round_id);
        return {
          id: bet.id,
          roundId: bet.round_id,
          roundNumber: round?.round_number || null,
          roundCode: round?.round_code || '-',
          betMap: bet.bet_map || {},
          totalCoins: bet.total_coins || 0,
          matchedNumber: bet.matched_number,
          payout: bet.payout || 0,
          result: bet.result || '-',
          createdAt: bet.created_at || null
        };
      });

    const transactions = db.transactions
      .filter(tx => tx.user_id === Number(user.id))
      .sort((a, b) => b.created_at - a.created_at)
      .map(tx => ({
        id: tx.id,
        type: tx.type,
        amount: tx.amount,
        meta: tx.meta || {},
        createdAt: tx.created_at || null
      }));

    const depositHistory = db.deposit_requests
      .filter(r => r.user_id === Number(user.id))
      .map(r => ({
        id: r.id,
        type: 'deposit',
        amount: r.amount,
        method: r.method || '',
        utr: r.utr || '',
        screenshot: r.screenshot || '',
        status: r.status,
        createdAt: r.created_at || null,
        updatedAt: r.updated_at || null
      }));

    const withdrawalHistory = db.withdraw_requests
      .filter(r => r.user_id === Number(user.id))
      .map(r => ({
        id: r.id,
        type: 'withdrawal',
        amount: r.amount,
        method: r.method || '',
        utr: '',
        screenshot: '',
        status: r.status,
        withdrawal_details: r.details || {},
        createdAt: r.created_at || null,
        updatedAt: r.updated_at || null
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
      history: {
        bets,
        transactions,
        requests
      }
    });
  } catch (error) {
    return res.status(500).json({ error: 'Unable to load user history' });
  }
});

app.get('/api/wallet-history', async (req, res) => {
  try {
    const userId = await getUserIdFromReq(req);
    if (!userId) {
      return res.status(401).json({ error: 'Login required' });
    }

    const user = await getUser(userId);
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }

    const requestItems = [
      ...(db.deposit_requests || [])
        .filter(request => request.user_id === user.id)
        .map(request => ({
          id: `deposit-request-${request.id}`,
          title: 'Deposit Request',
          amount: Math.abs(Number(request.amount || 0)),
          direction: 'debit',
          details: request.utr
            ? `UTR: ${request.utr}`
            : (request.method ? `Method: ${request.method}` : 'Deposit request submitted'),
          status: String(request.status || 'pending').toLowerCase(),
          createdAt: request.created_at || null,
          updatedAt: request.updated_at || null,
          group: 'request'
        })),

      ...(db.withdraw_requests || [])
        .filter(request => request.user_id === user.id)
        .map(request => ({
          id: `withdraw-request-${request.id}`,
          title: 'Withdrawal Request',
          amount: Math.abs(Number(request.amount || 0)),
          direction: 'debit',
          details: request.upiId
            ? `UPI ID: ${request.upiId}`
            : (request.method ? `Method: ${request.method}` : 'Withdrawal request submitted'),
          status: String(request.status || 'pending').toLowerCase(),
          createdAt: request.created_at || null,
          updatedAt: request.updated_at || null,
          group: 'request'
        }))
    ];

    const hiddenTxTypes = new Set([
      'deposit_request',
      'withdraw_request',
      'withdrawal_approved',
      'withdraw_rejected_refund',
      'withdraw_rejected'
    ]);

    const transactionItems = (db.transactions || [])
      .filter(tx => tx.user_id === user.id && !hiddenTxTypes.has(String(tx.type || '')))
      .map(tx => {
        let title = 'Wallet Activity';
        let details = 'Wallet activity';

        const amount = Math.abs(Number(tx.amount || 0));
        const direction = Number(tx.amount || 0) >= 0 ? 'credit' : 'debit';

        if (tx.type === 'deposit_approved') {
          title = 'Deposit Approved';
          details = 'Coins added by admin approval';
        } else if (tx.type === 'bet_debit') {
          title = 'Bet Placed / Loss';
          details = tx.meta?.roundId ? `Round ID: ${tx.meta.roundId}` : 'Bet amount deducted';
        } else if (tx.type === 'win_credit') {
          title = 'Winning Credit';
          details = tx.meta?.luckyNumber !== undefined
            ? `Lucky Number: ${tx.meta.luckyNumber}`
            : 'Winning amount added';
        } else if (tx.type === 'bonus_credit') {
          title = 'Daily Bonus';
          details = 'Bonus credited';
        } else if (tx.type === 'admin_add_coin') {
          title = 'Admin Added Coins';
          details = 'Coins added by admin';
        } else if (tx.type === 'admin_withdraw_coin') {
          title = 'Admin Removed Coins';
          details = 'Coins removed by admin';
        }

        return {
          id: tx.id,
          title,
          amount,
          direction,
          details,
          status: '',
          createdAt: tx.created_at || null,
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

    return res.json({
      success: true,
      history: items
    });
  } catch (error) {
    console.error('WALLET HISTORY ERROR:', error);
    return res.status(500).json({ error: 'Failed to load wallet history' });
  }
});

/* Compatibility aliases for existing frontend/admin */
app.post('/api/bet', (req, res) => app._router.handle({ ...req, url: '/api/place-bet', method: 'POST' }, res, () => {}));
app.post('/api/bonus', (req, res) => app._router.handle({ ...req, url: '/api/claim-bonus', method: 'POST' }, res, () => {}));

app.get('/api/admin/users', (req, res) => app._router.handle({ ...req, url: '/api/admin/load-users', method: 'GET' }, res, () => {}));
app.post('/api/admin/add-coins', async (req, res) => {
  const username = String(req.body?.username || '').trim();
  const amount = req.body?.amount;
  const user = await getUserByUsername(username);
  if (!user || user.is_admin === true) return res.status(404).json({ error: 'User not found' });
  req.body = { userId: user.id, amount };
  return app._router.handle({ ...req, url: '/api/admin/add-coin', method: 'POST' }, res, () => {});
});
app.post('/api/admin/withdraw-coins', async (req, res) => {
  const username = String(req.body?.username || '').trim();
  const amount = req.body?.amount;
  const user = await getUserByUsername(username);
  if (!user || user.is_admin === true) return res.status(404).json({ error: 'User not found' });
  req.body = { userId: user.id, amount };
  return app._router.handle({ ...req, url: '/api/admin/withdraw-coin', method: 'POST' }, res, () => {});
});
app.post('/api/admin/toggle-block-user', async (req, res) => {
  const username = String(req.body?.username || '').trim();
  const user = await getUserByUsername(username);
  if (!user || user.is_admin === true) return res.status(404).json({ error: 'User not found' });
  req.body = { userId: user.id };
  return app._router.handle({ ...req, url: '/api/admin/block-user', method: 'POST' }, res, () => {});
});
app.get('/api/admin/transactions', (req, res) => app._router.handle({ ...req, url: '/api/admin/transaction-history', method: 'GET' }, res, () => {}));
app.post('/api/admin/settle', (req, res) => app._router.handle({ ...req, url: '/api/admin/force-settle-round', method: 'POST' }, res, () => {}));

app.get('*', (req, res) => {
  return res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

(async () => {
  await testDB();
  await initDatabase();
  await ensureUsersSeeded();
  await ensureActiveRound();

  app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
  });
})();
