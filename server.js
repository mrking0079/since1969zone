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

const PORT = process.env.PORT || 3000;
const ADMIN_KEY = process.env.ADMIN_KEY || 'mrking0079';
const ROUND_SECONDS = 300;
const BETTING_CLOSE_SECONDS = 50;
const BONUS_AMOUNT = 50;
const BONUS_COOLDOWN_MS = 24 * 60 * 60 * 1000;
const PAYOUT_MULTIPLIER = 9;
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
  const key = req.header('x-admin-key');
  if (!key || key !== ADMIN_KEY) {
    return res.status(401).json({ error: 'Unauthorized admin access' });
  }
  next();
}

function createDefaultData() {
  return {
    users: [
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

function getUser(userId) {
  return db.users.find(u => u.id === userId) || null;
}
function getUserIdFromReq(req) {
  const id = Number(req.header('x-user-id'));
  if (!id) return DEMO_USER_ID;
  return id;
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

function getBetForRound(userId, roundId) {
  return db.bets.find(b => b.user_id === userId && b.round_id === roundId) || null;
}

function getRecentHistory(userId = DEMO_USER_ID, limit = 10) {
  return db.bets
    .filter(b => b.user_id === userId)
    .sort((a, b) => b.id - a.id)
    .slice(0, limit)
    .map(bet => {
      const round = db.rounds.find(r => r.id === bet.round_id) || {};
      return {
        id: bet.id,
        round_number: round.round_number,
        total_coins: bet.total_coins,
        matched_number: bet.matched_number,
        payout: bet.payout,
        result: bet.result,
        bet_map: bet.bet_map,
        lucky_number: round.lucky_number,
        server_seed_hash: round.server_seed_hash,
        server_seed: round.server_seed,
        client_seed: round.client_seed,
        created_at: bet.created_at
      };
    });
}

function createRound(roundNumber, startsAt) {
  const bettingClosesAt = startsAt + (ROUND_SECONDS - BETTING_CLOSE_SECONDS) * 1000;
  const endsAt = startsAt + ROUND_SECONDS * 1000;
  const serverSeed = randomHex(32);
  const clientSeed = `round-${roundNumber}-public-demo-seed`;
  const serverSeedHash = sha256(serverSeed);

  const round = {
    id: db.counters.roundId++,
    round_number: roundNumber,
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
  const current = getCurrentRound();
  const now = nowMs();

  if (!current) {
    return createRound(1, now);
  }

  if (current.status === 'open' && now >= current.betting_closes_at) {
    current.status = 'closed';
    saveData(db);
  }

  return getCurrentRound();
}

function createNextRoundIfNeeded() {
  const latest = [...db.rounds].sort((a, b) => b.round_number - a.round_number)[0];
  const active = getCurrentRound();
  if (active) return active;

  if (!latest) {
    return createRound(1, nowMs());
  }

  return createRound(latest.round_number + 1, nowMs());
}

function computeLuckyNumber(serverSeed, clientSeed, roundNumber) {
  const digest = sha256(`${serverSeed}:${clientSeed}:${roundNumber}`);
  const value = parseInt(digest.slice(0, 8), 16);
  return value % 10;
}

function getStatusForRound(round) {
  const now = nowMs();
  if (!round) return 'waiting';
  if (round.status === 'settled') return 'settled';
  if (now < round.betting_closes_at) return 'open';
  if (now < round.ends_at) return 'closed';
  return 'awaiting_settlement';
}

function syncRoundState() {
  const round = ensureActiveRound();
  if (!round) return null;

  const now = nowMs();
  if (round.status === 'open' && now >= round.betting_closes_at) {
    round.status = 'closed';
    saveData(db);
  }

  return round;
}

function buildGameState(userId = DEMO_USER_ID) {
  const round = syncRoundState();
  const user = getUser(userId);
  if (!user) {
    throw new Error('User not found');
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
      return res.status(400).json({ error: 'Username required hai' });
    }

    if (!password) {
      return res.status(400).json({ error: 'Password required hai' });
    }

    let user = db.users.find(
      u => String(u.username).toLowerCase() === username.toLowerCase()
    );

    if (!user) {
      user = {
        id: db.users.length ? Math.max(...db.users.map(u => u.id)) + 1 : 1,
        username,
        password,
        wallet_balance: 1250,
        total_played: 0,
        total_wins: 0,
        bonus_claimed: 0,
        last_bonus_time: 0,
        created_at: nowMs()
      };

      db.users.push(user);
      saveData(db);
    } else {
      if (String(user.password || '') !== password) {
        return res.status(401).json({ error: 'Galat password' });
      }
    }

    return res.json({
      success: true,
      user: {
        id: user.id,
        username: user.username,
        walletBalance: user.wallet_balance,
        totalPlayed: user.total_played,
        totalWins: user.total_wins,
        bonusClaimed: user.bonus_claimed,
        lastBonusTime: user.last_bonus_time
      }
    });
  } catch (error) {
    return res.status(500).json({ error: 'Login failed' });
  }
});
app.get('/api/state', (req, res) => {
  try {
    createNextRoundIfNeeded();
    const userId = getUserIdFromReq(req);
    return res.json(buildGameState(userId));
  } catch {
    return res.status(500).json({ error: 'Failed to load game state' });
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

app.post('/api/admin/credit', adminOnly, (req, res) => {
  try {
    const amount = Number(req.body?.amount);
    if (!Number.isInteger(amount) || amount <= 0 || amount > 100000) {
      return res.status(400).json({ error: 'Valid integer amount bhejo' });
    }

    const user = getUser(DEMO_USER_ID);
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }

    user.wallet_balance += amount;
    addTransaction(DEMO_USER_ID, 'admin_credit', amount, {});
    saveData(db);

    return res.json({ success: true, state: buildGameState() });
  } catch {
    return res.status(500).json({ error: 'Credit failed' });
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