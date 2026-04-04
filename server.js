import crypto from 'crypto';
import express from 'express';
import helmet from 'helmet';
import rateLimit from 'express-rate-limit';
import path from 'path';
import fs from 'fs';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
app.set('trust proxy', 1);

const PORT = process.env.PORT || 3000;
const ADMIN_KEY = process.env.ADMIN_KEY;
const ROUND_SECONDS = 60;
const BETTING_CLOSE_SECONDS = 10;
const BONUS_AMOUNT = 50;
const BONUS_COOLDOWN_MS = 24 * 60 * 60 * 1000;
const PAYOUT_MULTIPLIER = 8;
const DEMO_USER_ID = 1;
const DATA_FILE = path.join(__dirname, 'data.json');

app.use(helmet({
  contentSecurityPolicy: false
}));
app.use(express.json({ limit: '100kb' }));
app.use(rateLimit({
  windowMs: 60 * 1000,
  max: 120,
  standardHeaders: true,
  legacyHeaders: false
}));
app.use(express.static(path.join(__dirname, 'public')));

function nowMs() {
  return Date.now();
}

function sha256(value) {
  return crypto.createHash('sha256').update(value).digest('hex');
}

function randomHex(size = 32) {
  return crypto.randomBytes(size).toString('hex');
}

function jsonParseSafe(value, fallback) {
  try {
    return JSON.parse(value);
  } catch {
    return fallback;
  }
}

function adminOnly(req, res, next) {
  const userId = getUserIdFromReq(req);

  if (!userId) {
    return res.status(401).json({ error: 'Login required' });
  }

  const user = getUser(userId);

  if (!user) {
    return res.status(401).json({ error: 'User not found' });
  }

  if (String(user.username).toLowerCase() !== 'admin') {
    return res.status(403).json({ error: 'Admin access only' });
  }

  req.user = user;
  next();
}

function createDefaultData() {
  return {
    users: [
{
  id: 999,
  username: 'admin',
  password: 'admin123',
  session_token: '',
  wallet_balance: 0,
  total_played: 0,
  total_wins: 0,
  bonus_claimed: 0,
  last_bonus_time: 0,
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
        created_at: nowMs()
      }
    ],
    rounds: [],
    bets: [],
    transactions: [],
    counters: {
      roundId: 1,
      betId: 1,
      transactionId: 1
    }
  };
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

let db = loadData();

const adminExists = db.users.find(
  u => String(u.username).toLowerCase() === 'admin'
);

if (!adminExists) {
  db.users.unshift({
    id: 999,
    username: 'admin',
    password: 'admin123',
    session_token: '',
    wallet_balance: 0,
    total_played: 0,
    total_wins: 0,
    bonus_claimed: 0,
    last_bonus_time: 0,
    created_at: nowMs()
  });

  saveData(db);
}

function getUser(userId) {
  return db.users.find(u => u.id === userId) || null;
}
function getUserIdFromReq(req) {
  const token = String(req.header('x-auth-token') || '').trim();

  if (!token) {
    return null;
  }

  const user = db.users.find(u => String(u.session_token || '') === token);
  if (!user) {
    return null;
  }

  return user.id;
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

function ensureActiveRound() {
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
      settleRoundTx(latest.id);
      return createRound(latest.round_number + 1, nowMs());
    }

    return latest;
  }

  return createRound(latest.round_number + 1, now);
}

function createNextRoundIfNeeded() {
  return ensureActiveRound();
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

function syncRoundState() {
  return ensureActiveRound();
}

function buildGameState(userId = DEMO_USER_ID) {
  const round = syncRoundState();
  const user = getUser(userId);
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
    history
  };
}

function validateBetMap(betMap) {
  if (!betMap || typeof betMap !== 'object' || Array.isArray(betMap)) {
    return { ok: false, error: 'Invalid bet map' };
  }

  const keys = Object.keys(betMap);
  if (keys.length === 0) {
    return { ok: false, error: 'At least one number select karo' };
  }
  if (keys.length > 10) {
    return { ok: false, error: 'Too many selections' };
  }

  let total = 0;
  const sanitized = {};

  for (const key of keys) {
    if (!/^\d$/.test(key)) {
      return { ok: false, error: 'Number sirf 0 se 9 tak allowed hai' };
    }
    const amount = Number(betMap[key]);
    if (!Number.isInteger(amount) || amount <= 0) {
      return { ok: false, error: 'Har bet amount positive integer hona chahiye' };
    }
    if (amount > 10000) {
      return { ok: false, error: 'Single number amount limit 10000 hai' };
    }
    total += amount;
    sanitized[key] = amount;
  }

  if (total < 1) {
    return { ok: false, error: 'Minimum total bet 1 coin hai' };
  }
  if (total > 50000) {
    return { ok: false, error: 'Maximum total bet 50000 coins hai' };
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

function placeBetTx(userId, roundId, betMap, totalCoins) {
  const user = getUser(userId);
  if (!user) throw new Error('User not found');
  if (user.wallet_balance < totalCoins) throw new Error('Insufficient wallet balance');

  const existingBet = getBetForRound(userId, roundId);
  if (existingBet) throw new Error('Is round ke liye bet already place ho chuka hai');

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

  user.wallet_balance -= totalCoins;
  user.total_played += totalCoins;

  addTransaction(userId, 'bet_debit', -totalCoins, { roundId });
  saveData(db);
}

function claimBonusTx(userId) {
  const user = getUser(userId);
  if (!user) throw new Error('User not found');

  const current = nowMs();
  if (current - user.last_bonus_time < BONUS_COOLDOWN_MS) {
    throw new Error('Bonus abhi available nahi hai');
  }

  user.wallet_balance += BONUS_AMOUNT;
  user.bonus_claimed += 1;
  user.last_bonus_time = current;

  addTransaction(userId, 'bonus_credit', BONUS_AMOUNT, {});
  saveData(db);
}

function settleRoundTx(roundId) {
  const round = db.rounds.find(r => r.id === roundId);
  if (!round) throw new Error('Round not found');
  if (round.status === 'settled') throw new Error('Round already settled');
  if (nowMs() < round.ends_at) throw new Error('Round timer abhi khatam nahi hua');

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
      const user = getUser(bet.user_id);
      if (user) {
        user.wallet_balance += payout;
        user.total_wins += 1;
      }

      addTransaction(bet.user_id, 'win_credit', payout, {
        roundId: round.id,
        luckyNumber
      });
    }
  }

  saveData(db);
}
app.post('/api/login', (req, res) => {
  try {
    const username = String(req.body?.username || '').trim();
    const password = String(req.body?.password || '').trim();

    if (!username) {
      return res.status(400).json({ error: 'Username required' });
    }

    if (!password) {
      return res.status(400).json({ error: 'Password required' });
    }

    let user = db.users.find(
      u => String(u.username).toLowerCase() === username.toLowerCase()
    );

    if (!user) {
      return res.status(404).json({ error: 'username not exists signup first' });
    }
        if (String(user.password || '') !== password) {
      return res.status(401).json({ error: 'Wrong password' });
    }

user.session_token = crypto.randomUUID();
    return res.json({
      success: true,
      user: {
        id: user.id,
        username: user.username,
        sessionToken: user.session_token,
        walletBalance: user.wallet_balance,
        totalPlayed: user.total_played,
        totalWins: user.total_wins,
        bonusClaimed: user.bonus_claimed,
        lastBonusTime: user.last_bonus_time
      }
    });
  } catch {
    return res.status(500).json({ error: 'Login failed' });
  }
});
app.post('/api/signup', (req, res) => {
  try {
    const username = String(req.body?.username || '').trim();
    const password = String(req.body?.password || '').trim();

    if (!username) {
      return res.status(400).json({ error: 'Username required' });
    }

    if (!password) {
      return res.status(400).json({ error: 'Password required' });
    }

    const existingUser = db.users.find(
      u => String(u.username).toLowerCase() === username.toLowerCase()
    );

    if (existingUser) {
      return res.status(409).json({ error: 'Username Alerdy exists' });
    }

    const user = {
      id: db.users.length ? Math.max(...db.users.map(u => u.id)) + 1 : 1,
      username,
      password,
      session_token: crypto.randomUUID(),
      wallet_balance: 1000,
      total_played: 0,
      total_wins: 0,
      bonus_claimed: 0,
      last_bonus_time: 0,
      created_at: nowMs()
    };

    db.users.push(user);
    saveData(db);

    return res.json({
      success: true,
      message: 'Signup successful',
      user: {
        id: user.id,
        username: user.username,
sessionToken: user.session_token,
        walletBalance: user.wallet_balance,
        totalPlayed: user.total_played,
        totalWins: user.total_wins,
        bonusClaimed: user.bonus_claimed,
        lastBonusTime: user.last_bonus_time
      }
    });
  } catch {
    return res.status(500).json({ error: 'Signup failed' });
  }
});
app.get('/api/state', (req, res) => {
  try {
    createNextRoundIfNeeded();
    const userId = getUserIdFromReq(req);
    return res.json(buildGameState(userId));
  } catch (err) {
  console.error('STATE ERROR:', err);
  return res.status(500).json({ error: err.message });
}
});

app.post('/api/bet', (req, res) => {
  try {
    const userId = getUserIdFromReq(req);
    const round = syncRoundState();

    if (!round) {
      return res.status(400).json({ error: 'No active round available' });
    }

    const roundStatus = getStatusForRound(round);
    if (roundStatus !== 'open') {
      return res.status(400).json({ error: 'Betting abhi open nahi hai' });
    }

    const validation = validateBetMap(req.body?.betMap);
    if (!validation.ok) {
      return res.status(400).json({ error: validation.error });
    }

    placeBetTx(userId, round.id, validation.sanitized, validation.total);

    return res.json({
      success: true,
      message: 'Bet successfully place ho gaya',
      state: buildGameState(userId)
    });
  } catch (error) {
    return res.status(400).json({ error: error.message || 'Bet place nahi hua' });
  }
});

app.post('/api/bonus', (req, res) => {
  try {
    const userId = getUserIdFromReq(req);
    claimBonusTx(userId);
    return res.json({
      success: true,
      message: `${BONUS_AMOUNT} coins bonus add ho gaye`,
      state: buildGameState(userId)
    });
  } catch (error) {
    return res.status(400).json({ error: error.message || 'Bonus claim failed' });
  }
});

app.post('/api/admin/settle', adminOnly, (req, res) => {
  try {
    const round = syncRoundState();
    if (!round) {
      return res.status(400).json({ error: 'No round found' });
    }
    settleRoundTx(round.id);
    createNextRoundIfNeeded();
    return res.json({
      success: true,
      message: 'Round settled successfully',
      state: buildGameState()
    });
  } catch (error) {
    return res.status(400).json({ error: error.message || 'Settlement failed' });
  }
});

app.get('/api/admin/users', adminOnly, (req, res) => {
  try {
    const users = db.users.map(user => ({
      id: user.id,
      username: user.username,
      walletBalance: user.wallet_balance || 0,
      totalPlayed: user.total_played || 0,
      totalWins: user.total_wins || 0,
      bonusClaimed: user.bonus_claimed || 0,
      createdAt: user.created_at || null
    }));

    return res.json({
      success: true,
      users
    });
  } catch (error) {
    return res.status(500).json({ error: 'Failed to load users' });
  }
});

app.get('*', (req, res) => {
  return res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

ensureActiveRound();

app.listen(PORT, () => {
  console.log(`Secure game server running on http://localhost:${PORT}`);
  console.log('Set ADMIN_KEY env var before production use.');
});