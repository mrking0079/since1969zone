import crypto from 'crypto';
import express from 'express';
import helmet from 'helmet';
import path from 'path';
import fs from 'fs';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
app.set('trust proxy', 1);

const PORT = process.env.PORT || 3000;
const ADMIN_KEY = process.env.ADMIN_KEY || 'dev-admin-key';

const ROUND_SECONDS = 120;              // full round = 2 min
const BETTING_CLOSE_SECONDS = 30;       // last 30 sec close
const BONUS_AMOUNT = 50;
const BONUS_COOLDOWN_MS = 24 * 60 * 60 * 1000;
const PAYOUT_MULTIPLIER = 9;

const DATA_FILE = path.join(process.cwd(), 'data.json');

app.use(helmet({
contentSecurityPolicy: false
}));
app.use(express.json({ limit: '100kb' }));
app.use(express.static(path.join(__dirname, 'public')));

// =====================================
// BASIC HELPERS
// =====================================
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

// =====================================
// DATA
// =====================================
function createDefaultData() {
return {
users: [],
rounds: [],
bets: [],
transactions: [],
counters: {
userId: 1,
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

// =====================================
// USERS
// =====================================
function getUser(userId) {
return db.users.find(u => u.id === userId) || null;
}

function getUserByUsername(username) {
return db.users.find(
u => String(u.username).toLowerCase() === String(username).toLowerCase()
) || null;
}

function getUserIdFromReq(req) {
const id = Number(req.header('x-user-id'));
if (!id || !Number.isInteger(id)) return null;

const user = getUser(id);
if (!user) return null;

return id;
}

// =====================================
// ROUNDS
// =====================================
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

function getCurrentRound() {
const latest = [...db.rounds].sort((a, b) => b.round_number - a.round_number)[0];
return latest || null;
}

function getLastSettledRound() {
return [...db.rounds]
.filter(r => r.status === 'settled')
.sort((a, b) => b.round_number - a.round_number)[0] || null;
}

function getRecentResults(limit = 10) {
return [...db.rounds]
.filter(r => r.status === 'settled')
.sort((a, b) => b.round_number - a.round_number)
.slice(0, limit)
.map(r => ({
round_number: r.round_number,
lucky_number: r.lucky_number
}));
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
return 'closed';
}

function getBetsForRound(roundId) {
return db.bets.filter(b => b.round_id === roundId);
}

function ensureActiveRound() {
const latest = getCurrentRound();
const now = nowMs();

if (!latest) {
return createRound(1, now);
}

if (latest.status !== 'settled') {
if (latest.status === 'open' && now >= latest.betting_closes_at) {
latest.status = 'closed';
saveData(db);
}

```
if (now >= latest.ends_at) {
  settleRoundTx(latest.id);
  return createRound(latest.round_number + 1, nowMs());
}

return latest;
```

}

return createRound(latest.round_number + 1, now);
}

function syncRoundState() {
return ensureActiveRound();
}

// =====================================
// BETS / BONUS / TX
// =====================================
function validateBetMap(betMap) {
if (!betMap || typeof betMap !== 'object' || Array.isArray(betMap)) {
return { ok: false, error: 'Invalid bet map' };
}

const keys = Object.keys(betMap);
if (keys.length === 0) {
return { ok: false, error: 'At least one number select karo' };
}

let total = 0;
const sanitized = {};

for (const key of keys) {
if (!/^\d$/.test(key)) {
return { ok: false, error: 'Sirf 0 se 9 tak allowed hai' };
}

```
const amount = Number(betMap[key]);
if (!Number.isInteger(amount) || amount <= 0) {
  return { ok: false, error: 'Amount positive integer hona chahiye' };
}

total += amount;
sanitized[key] = amount;
```

}

if (total < 1) {
return { ok: false, error: 'Minimum bet 1 hai' };
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

function getBetForRound(userId, roundId) {
return db.bets.find(b => b.user_id === userId && b.round_id === roundId) || null;
}

function placeBetTx(userId, roundId, betMap, totalCoins) {
const user = getUser(userId);
if (!user) throw new Error('User not found');

if (user.wallet_balance < totalCoins) {
throw new Error('Insufficient balance');
}

const existingBet = getBetForRound(userId, roundId);
if (existingBet) {
throw new Error('Is round ke liye bet already place ho chuka hai');
}

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
if (round.status === 'settled') return;

const luckyNumber = computeLuckyNumber(
round.server_seed,
round.client_seed,
round.round_number
);

round.status = 'settled';
round.lucky_number = luckyNumber;
round.settled_at = nowMs();

const bets = db.bets.filter(b => b.round_id === round.id);

for (const bet of bets) {
const matchedAmount = Number(bet.bet_map[String(luckyNumber)] || 0);
const payout = matchedAmount > 0 ? matchedAmount * PAYOUT_MULTIPLIER : 0;
const result = payout > 0 ? 'win' : 'lose';

```
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
```

}

saveData(db);
}

// =====================================
// GAME STATE
// =====================================
function buildGameState(userId) {
const round = syncRoundState();
const user = getUser(userId);

if (!user) {
throw new Error('User not found');
}

const placedBet = round ? getBetForRound(userId, round.id) : null;

return {
user: {
id: user.id,
username: user.username,
wallet_balance: user.wallet_balance,
total_played: user.total_played,
total_wins: user.total_wins,
bonus_claimed: user.bonus_claimed,
last_bonus_time: user.last_bonus_time
},
balance: user.wallet_balance,
round: round ? {
id: round.id,
round_number: round.round_number,
starts_at: round.starts_at,
betting_closes_at: round.betting_closes_at,
ends_at: round.ends_at,
status: getStatusForRound(round),
lucky_number: round.lucky_number,
server_seed_hash: round.server_seed_hash,
already_placed: Boolean(placedBet)
} : null,
placedBet: placedBet ? {
total_coins: placedBet.total_coins,
bet_map: placedBet.bet_map,
result: placedBet.result,
payout: placedBet.payout
} : null,
lastResults: getRecentResults(10)
};
}

// =====================================
// ADMIN
// =====================================
function adminOnly(req, res, next) {
const key = req.header('x-admin-key');
if (!key || key !== ADMIN_KEY) {
return res.status(401).json({ error: 'Unauthorized admin access' });
}
next();
}

// =====================================
// ROUTES
// =====================================

// LOGIN / REGISTER
app.post('/api/login', (req, res) => {
try {
const username = String(req.body?.username || '').trim();
const password = String(req.body?.password || '').trim();

```
if (!username) {
  return res.status(400).json({ error: 'Username required hai' });
}

if (!password) {
  return res.status(400).json({ error: 'Password required hai' });
}

let user = getUserByUsername(username);

if (!user) {
  user = {
    id: db.counters.userId++,
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
    username: user.username
  }
});
```

} catch (error) {
return res.status(500).json({ error: 'Login failed' });
}
});

// STATE
app.get('/api/state', (req, res) => {
try {
const userId = getUserIdFromReq(req);

```
if (!userId) {
  return res.status(401).json({ error: 'User session invalid' });
}

return res.json(buildGameState(userId));
```

} catch (err) {
return res.status(500).json({
error: 'Failed to load game state',
message: err.message
});
}
});

// BET
app.post('/api/bet', (req, res) => {
try {
const userId = getUserIdFromReq(req);
if (!userId) {
return res.status(401).json({ error: 'User session invalid' });
}

```
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
```

} catch (error) {
return res.status(400).json({ error: error.message || 'Bet place nahi hua' });
}
});

// BONUS
app.post('/api/bonus', (req, res) => {
try {
const userId = getUserIdFromReq(req);
if (!userId) {
return res.status(401).json({ error: 'User session invalid' });
}

```
claimBonusTx(userId);

return res.json({
  success: true,
  message: `${BONUS_AMOUNT} coins bonus add ho gaye`,
  state: buildGameState(userId)
});
```

} catch (error) {
return res.status(400).json({ error: error.message || 'Bonus claim failed' });
}
});

// ADMIN SETTLE
app.post('/api/admin/settle', adminOnly, (req, res) => {
try {
const round = syncRoundState();
if (!round) {
return res.status(400).json({ error: 'No round found' });
}

```
settleRoundTx(round.id);
ensureActiveRound();

return res.json({
  success: true,
  message: 'Round settled successfully'
});
```

} catch (error) {
return res.status(400).json({ error: error.message || 'Settlement failed' });
}
});

// ADMIN CREDIT
app.post('/api/admin/credit', adminOnly, (req, res) => {
try {
const userId = Number(req.body?.userId);
const amount = Number(req.body?.amount);

```
if (!userId || !Number.isInteger(userId)) {
  return res.status(400).json({ error: 'Valid userId bhejo' });
}

if (!Number.isInteger(amount) || amount <= 0 || amount > 100000) {
  return res.status(400).json({ error: 'Valid integer amount bhejo' });
}

const user = getUser(userId);
if (!user) {
  return res.status(404).json({ error: 'User not found' });
}

user.wallet_balance += amount;
addTransaction(userId, 'admin_credit', amount, {});
saveData(db);

return res.json({
  success: true,
  message: 'Credit added successfully',
  state: buildGameState(userId)
});
```

} catch (error) {
return res.status(500).json({ error: 'Credit failed' });
}
});

// ADMIN ANNOUNCE (manual force result)
app.post('/api/admin/announce', adminOnly, (req, res) => {
try {
const result = Number(req.body?.result);

```
if (!Number.isInteger(result) || result < 0 || result > 9) {
  return res.status(400).json({ error: 'Result must be between 0 and 9' });
}

const current = getCurrentRound();
if (!current) {
  return res.status(404).json({ error: 'No active round found' });
}

current.lucky_number = result;
current.status = 'settled';
current.settled_at = nowMs();

const bets = getBetsForRound(current.id);

for (const bet of bets) {
  const matchedAmount = Number(bet.bet_map[String(result)] || 0);
  const payout = matchedAmount > 0 ? matchedAmount * PAYOUT_MULTIPLIER : 0;
  const outcome = payout > 0 ? 'win' : 'lose';

  bet.matched_number = result;
  bet.payout = payout;
  bet.result = outcome;

  if (payout > 0) {
    const user = getUser(bet.user_id);
    if (user) {
      user.wallet_balance += payout;
      user.total_wins += 1;
    }

    addTransaction(bet.user_id, 'manual_win_credit', payout, {
      roundId: current.id,
      luckyNumber: result
    });
  }
}

saveData(db);
ensureActiveRound();

return res.json({
  success: true,
  message: 'Result announced successfully',
  round_number: current.round_number,
  lucky_number: current.lucky_number
});
```

} catch (err) {
return res.status(500).json({
error: 'Announce failed',
message: err.message
});
}
});

// FRONTEND FALLBACK
app.get('*', (req, res) => {
return res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// START
ensureActiveRound();

app.listen(PORT, () => {
console.log(`Since1969zone running on http://localhost:${PORT}`);
console.log('Render + Node deploy ready.');
});
