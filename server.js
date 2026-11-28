const path = require('node:path');
const crypto = require('node:crypto');
const http = require('node:http');
const express = require('express');
const session = require('express-session');
const MySQLStore = require('express-mysql-session')(session);
const bcrypt = require('bcryptjs');
const { Server } = require('socket.io');
const webauthn = require('@simplewebauthn/server');
const { pool, init, url } = require('./db');
const mail = require('./mail');

const CATEGORIES = ['연애', '인간관계', '진로', '학업', '가족', '직장', '건강', '기타'];
const MAX_MSG = 2000;

const app = express();
app.set('trust proxy', 1);
app.use(express.json({ limit: '20kb' }));

const u = new URL(url);
const store = new MySQLStore({
  host: u.hostname, port: Number(u.port || 3306),
  user: decodeURIComponent(u.username), password: decodeURIComponent(u.password),
  database: u.pathname.slice(1),
});
const SESSION_SECRET = process.env.SESSION_SECRET || 'dev-secret-change-me';
const sessionMw = session({
  secret: SESSION_SECRET,
  store, resave: false, saveUninitialized: false,
  cookie: { httpOnly: true, sameSite: 'lax', secure: 'auto', maxAge: 1000 * 60 * 60 * 24 * 30 },
});
app.use(sessionMw);

const q = async (sql, params) => (await pool.query(sql, params))[0];
const pub = (x) => x && { id: x.id, nickname: x.nickname, role: x.role, is_anonymous: !!x.is_anonymous, email: x.email };

async function getUser(id) {
  if (!id) return null;
  const [user] = await q('SELECT * FROM users WHERE id = ?', [id]);
  return user && !user.banned ? user : null;
}

// 세션의 버전이 회원의 session_ver 와 다르면 (비밀번호 변경·다른 기기 로그아웃) 무효
const sessionOk = (user, sess) => !!user && (sess?.ver ?? 0) === user.session_ver;
async function sessionUser(sess) {
  const user = await getUser(sess?.userId);
  return sessionOk(user, sess) ? user : null;
}

// 매 요청마다 DB에서 다시 읽는다 → 역할 변경·정지가 즉시 반영된다
app.use(async (req, res, next) => {
  try { req.user = await sessionUser(req.session); next(); } catch (e) { next(e); }
});

const wrap = (fn) => (req, res, next) => fn(req, res, next).catch(next);
const auth = (...roles) => (req, res, next) => {
  if (!req.user) return res.status(401).json({ error: '로그인이 필요해요.' });
  if (roles.length && !roles.includes(req.user.role)) return res.status(403).json({ error: '권한이 없어요.' });
  next();
};
const isStaff = (user) => user.role === 'counselor' || user.role === 'admin';

async function access(user, id) {
  const [c] = await q('SELECT * FROM consultations WHERE id = ?', [id]);
  if (!c) return null;
  const ok = user.role === 'admin' || c.client_id === user.id || c.counselor_id === user.id
    || (c.status === 'waiting' && user.role === 'counselor');
  return ok ? c : null;
}

function login(req, user) {
  return new Promise((resolve, reject) =>
    req.session.regenerate((err) => {
      if (err) return reject(err);
      req.session.userId = user.id;
      req.session.ver = user.session_ver;
      req.session.save((e) => (e ? reject(e) : resolve()));
    }));
}

// ponytail: 메모리 카운터 — 인스턴스 1개 한정. 여러 대로 늘리면 Redis 등으로.
const fails = new Map();
function tooMany(key) {
  const f = fails.get(key);
  if (f && Date.now() - f.t > 15 * 60 * 1000) { fails.delete(key); return false; }
  return f && f.n >= 10;
}
function fail(key) {
  const f = fails.get(key) || { n: 0, t: Date.now() };
  f.n++; fails.set(key, f);
}

app.get('/healthz', (req, res) => res.type('text').send('ok\n'));

app.get('/api/me', (req, res) => res.json({ user: pub(req.user), categories: CATEGORIES }));

app.post('/api/anon', wrap(async (req, res) => {
  if (req.user) return res.json({ user: pub(req.user) });
  const nick = '익명#' + String(Math.floor(1000 + Math.random() * 9000));
  const r = await q('INSERT INTO users (nickname, is_anonymous) VALUES (?, 1)', [nick]);
  const user = await getUser(r.insertId);
  await login(req, user);
  res.json({ user: pub(user) });
}));

const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
const normEmail = (v) => String(v || '').trim().toLowerCase();
const sha = (v) => crypto.createHash('sha256').update(v).digest('hex');

// 회원가입 이메일 인증번호 발송 (6자리, 10분 유효, 재발송 1분 간격, 입력 5회까지)
app.post('/api/email/code', wrap(async (req, res) => {
  const email = normEmail(req.body.email);
  if (!EMAIL_RE.test(email) || email.length > 190) return res.status(400).json({ error: '이메일 형식을 확인해주세요.' });
  if (!mail.enabled) return res.status(503).json({ error: '지금은 인증 메일을 보낼 수 없어요. 관리자에게 문의해주세요.' });
  const key = 'mail:' + req.ip;
  if (tooMany(key)) return res.status(429).json({ error: '요청이 너무 많아요. 잠시 후 다시 해주세요.' });
  const [dup] = await q('SELECT id FROM users WHERE email = ?', [email]);
  if (dup) return res.status(409).json({ error: '이미 가입된 이메일이에요.' });
  const [prev] = await q('SELECT sent_at > NOW() - INTERVAL 60 SECOND AS recent FROM email_codes WHERE email = ?', [email]);
  if (prev?.recent) return res.status(429).json({ error: '인증번호는 1분에 한 번만 보낼 수 있어요.' });
  fail(key);
  const code = String(crypto.randomInt(0, 1_000_000)).padStart(6, '0');
  await q('REPLACE INTO email_codes (email, code_hash, expires_at) VALUES (?, ?, NOW() + INTERVAL 10 MINUTE)', [email, sha(code)]);
  try {
    await mail.send({ to: email, ...mail.verifyCode(code) });
  } catch (e) {
    console.error('mail send failed', e);
    await q('DELETE FROM email_codes WHERE email = ?', [email]);
    return res.status(502).json({ error: '메일을 보내지 못했어요. 주소를 확인하고 다시 시도해주세요.' });
  }
  res.json({ ok: true });
}));

app.post('/api/signup', wrap(async (req, res) => {
  const email = normEmail(req.body.email);
  const password = String(req.body.password || '');
  const nickname = String(req.body.nickname || '').trim();
  const code = String(req.body.code || '').trim();
  if (!EMAIL_RE.test(email) || email.length > 190) return res.status(400).json({ error: '이메일 형식을 확인해주세요.' });
  if (password.length < 8 || password.length > 72) return res.status(400).json({ error: '비밀번호는 8~72자로 해주세요.' });
  if (nickname.length < 1 || nickname.length > 20) return res.status(400).json({ error: '닉네임은 1~20자로 해주세요.' });
  if (!/^\d{6}$/.test(code)) return res.status(400).json({ error: '이메일로 받은 6자리 인증번호를 입력해주세요.' });
  // 시도 횟수를 먼저 원자적으로 올린다 → 동시 요청으로 5회 제한을 넘길 수 없다
  const r0 = await q('UPDATE email_codes SET attempts = attempts + 1 WHERE email = ? AND attempts < 5 AND expires_at > NOW()', [email]);
  if (!r0.affectedRows) return res.status(400).json({ error: '인증번호가 만료됐어요. 다시 받아주세요.' });
  const [ec] = await q('SELECT code_hash FROM email_codes WHERE email = ?', [email]);
  if (!ec || !crypto.timingSafeEqual(Buffer.from(sha(code)), Buffer.from(ec.code_hash)))
    return res.status(400).json({ error: '인증번호가 맞지 않아요.' });
  try {
    const r = await q('INSERT INTO users (email, password_hash, nickname) VALUES (?, ?, ?)',
      [email, await bcrypt.hash(password, 10), nickname]);
    await q('DELETE FROM email_codes WHERE email = ?', [email]);
    const user = await getUser(r.insertId);
    await login(req, user);
    res.json({ user: pub(user) });
  } catch (e) {
    if (e.code === 'ER_DUP_ENTRY') return res.status(409).json({ error: '이미 가입된 이메일이에요.' });
    throw e;
  }
}));

app.post('/api/login', wrap(async (req, res) => {
  const key = req.ip;
  if (tooMany(key)) return res.status(429).json({ error: '시도가 너무 많아요. 잠시 후 다시 해주세요.' });
  const email = String(req.body.email || '').trim().toLowerCase();
  const [user] = await q('SELECT * FROM users WHERE email = ?', [email]);
  if (!user || !(await bcrypt.compare(String(req.body.password || ''), user.password_hash || ''))) {
    fail(key);
    return res.status(401).json({ error: '이메일 또는 비밀번호가 맞지 않아요.' });
  }
  if (user.banned) return res.status(403).json({ error: '이용이 정지된 계정이에요.' });
  fails.delete(key);
  await login(req, user);
  res.json({ user: pub(user) });
}));

app.post('/api/logout', (req, res) => req.session.destroy(() => res.json({ ok: true })));

// ── 내 정보 ──
app.get('/api/account', auth(), (req, res) => {
  res.json({ user: { ...pub(req.user), created_at: req.user.created_at } });
});

app.post('/api/account/nickname', auth(), wrap(async (req, res) => {
  if (req.user.is_anonymous) return res.status(403).json({ error: '회원만 닉네임을 바꿀 수 있어요.' });
  const nickname = String(req.body.nickname || '').trim();
  if (nickname.length < 1 || nickname.length > 20) return res.status(400).json({ error: '닉네임은 1~20자로 해주세요.' });
  await q('UPDATE users SET nickname = ? WHERE id = ?', [nickname, req.user.id]);
  res.json({ user: pub({ ...req.user, nickname }) });
}));

// 다른 기기의 세션은 session_ver 를 올려 끊고, 지금 세션만 새 버전으로 다시 로그인
async function bumpSessions(req) {
  await q('UPDATE users SET session_ver = session_ver + 1 WHERE id = ?', [req.user.id]);
  await login(req, await getUser(req.user.id));
}

app.post('/api/account/password', auth(), wrap(async (req, res) => {
  if (req.user.is_anonymous) return res.status(403).json({ error: '회원만 비밀번호를 바꿀 수 있어요.' });
  const key = 'pw:' + req.user.id;
  if (tooMany(key)) return res.status(429).json({ error: '시도가 너무 많아요. 잠시 후 다시 해주세요.' });
  const password = String(req.body.password || '');
  if (password.length < 8 || password.length > 72) return res.status(400).json({ error: '새 비밀번호는 8~72자로 해주세요.' });
  if (!(await bcrypt.compare(String(req.body.current || ''), req.user.password_hash || ''))) {
    fail(key);
    return res.status(400).json({ error: '현재 비밀번호가 맞지 않아요.' });
  }
  fails.delete(key);
  await q('UPDATE users SET password_hash = ? WHERE id = ?', [await bcrypt.hash(password, 10), req.user.id]);
  await bumpSessions(req);
  res.json({ ok: true });
}));

app.post('/api/account/logout-others', auth(), wrap(async (req, res) => {
  await bumpSessions(req);
  res.json({ ok: true });
}));

// ── 패스키 (WebAuthn) ──
// RP ID·origin 은 요청 호스트에서 정한다 (trust proxy 로 X-Forwarded-* 반영). 고정하려면 env 로.
const rp = (req) => ({
  rpID: process.env.WEBAUTHN_RP_ID || req.hostname,
  origin: process.env.WEBAUTHN_ORIGIN || `${req.protocol}://${req.get('host')}`,
});
// 인증기에 저장되는 사용자 핸들: 회원 id 를 그대로 노출하지 않으면서 회원마다 고정된 값
const userHandle = (id) => crypto.createHmac('sha256', SESSION_SECRET).update('passkey:' + id).digest();
const b64url = (buf) => Buffer.from(buf).toString('base64url');
// 챌린지는 한 번만 쓸 수 있게 꺼내면서 지운다 (5분 유효)
function takeChallenge(req, kind) {
  const c = req.session.webauthn;
  delete req.session.webauthn;
  return c && c.kind === kind && c.exp > Date.now() ? c.challenge : null;
}
const keepChallenge = (req, kind, challenge) => { req.session.webauthn = { kind, challenge, exp: Date.now() + 5 * 60 * 1000 }; };
const member = (req, res, next) => (req.user?.is_anonymous ? res.status(403).json({ error: '회원만 패스키를 쓸 수 있어요.' }) : next());

app.post('/api/passkey/register/options', auth(), member, wrap(async (req, res) => {
  const mine = await q('SELECT id, transports FROM passkeys WHERE user_id = ?', [req.user.id]);
  if (mine.length >= 10) return res.status(400).json({ error: '패스키는 10개까지 등록할 수 있어요.' });
  const options = await webauthn.generateRegistrationOptions({
    rpName: 'Love Design',
    rpID: rp(req).rpID,
    userID: userHandle(req.user.id),
    userName: req.user.email,
    userDisplayName: req.user.nickname,
    attestationType: 'none',
    excludeCredentials: mine.map((p) => ({ id: p.id, transports: p.transports ? p.transports.split(',') : undefined })),
    authenticatorSelection: { residentKey: 'required', userVerification: 'required' },
  });
  keepChallenge(req, 'register', options.challenge);
  res.json(options);
}));

app.post('/api/passkey/register/verify', auth(), member, wrap(async (req, res) => {
  const expectedChallenge = takeChallenge(req, 'register');
  if (!expectedChallenge) return res.status(400).json({ error: '시간이 지났어요. 다시 시도해주세요.' });
  const { rpID, origin } = rp(req);
  let v;
  try {
    v = await webauthn.verifyRegistrationResponse({
      response: req.body.response, expectedChallenge, expectedOrigin: origin, expectedRPID: rpID, requireUserVerification: true,
    });
  } catch (e) {
    console.warn('passkey register verify failed', e.message);
  }
  if (!v?.verified) return res.status(400).json({ error: '패스키를 확인하지 못했어요.' });
  const { credential, passkeyProviderMetadata } = v.registrationInfo;
  const name = String(req.body.name || passkeyProviderMetadata?.name || '패스키').trim().slice(0, 60) || '패스키';
  try {
    await q('INSERT INTO passkeys (id, user_id, public_key, counter, transports, name) VALUES (?, ?, ?, ?, ?, ?)',
      [credential.id, req.user.id, Buffer.from(credential.publicKey), credential.counter, credential.transports?.join(',') || null, name]);
  } catch (e) {
    if (e.code === 'ER_DUP_ENTRY') return res.status(409).json({ error: '이미 등록된 패스키예요.' });
    throw e;
  }
  res.json({ ok: true });
}));

app.get('/api/passkeys', auth(), member, wrap(async (req, res) => {
  res.json(await q('SELECT id, name, created_at, last_used_at FROM passkeys WHERE user_id = ? ORDER BY created_at', [req.user.id]));
}));

app.post('/api/passkeys/delete', auth(), member, wrap(async (req, res) => {
  const r = await q('DELETE FROM passkeys WHERE id = ? AND user_id = ?', [String(req.body.id || ''), req.user.id]);
  if (!r.affectedRows) return res.status(404).json({ error: '없는 패스키예요.' });
  res.json({ ok: true });
}));

// 아이디 입력 없이 로그인 (discoverable credential) → allowCredentials 를 비워 둔다
app.post('/api/passkey/login/options', wrap(async (req, res) => {
  const options = await webauthn.generateAuthenticationOptions({ rpID: rp(req).rpID, userVerification: 'required' });
  keepChallenge(req, 'login', options.challenge);
  res.json(options);
}));

app.post('/api/passkey/login/verify', wrap(async (req, res) => {
  const key = req.ip;
  if (tooMany(key)) return res.status(429).json({ error: '시도가 너무 많아요. 잠시 후 다시 해주세요.' });
  const expectedChallenge = takeChallenge(req, 'login');
  if (!expectedChallenge) return res.status(400).json({ error: '시간이 지났어요. 다시 시도해주세요.' });
  const response = req.body.response;
  const [pk] = await q('SELECT * FROM passkeys WHERE id = ?', [String(response?.id || '')]);
  const denied = () => { fail(key); return res.status(401).json({ error: '등록되지 않은 패스키예요. 비밀번호로 로그인한 뒤 내 정보에서 등록해주세요.' }); };
  if (!pk) return denied();
  if (response.response?.userHandle && response.response.userHandle !== b64url(userHandle(pk.user_id))) return denied();
  const { rpID, origin } = rp(req);
  let v;
  try {
    v = await webauthn.verifyAuthenticationResponse({
      response, expectedChallenge, expectedOrigin: origin, expectedRPID: rpID, requireUserVerification: true,
      credential: { id: pk.id, publicKey: new Uint8Array(pk.public_key), counter: Number(pk.counter), transports: pk.transports?.split(',') },
    });
  } catch (e) {
    console.warn('passkey login verify failed', e.message);
  }
  if (!v?.verified) return denied();
  const user = await getUser(pk.user_id);
  if (!user) return res.status(403).json({ error: '이용이 정지된 계정이에요.' });
  await q('UPDATE passkeys SET counter = ?, last_used_at = NOW() WHERE id = ?', [v.authenticationInfo.newCounter, pk.id]);
  fails.delete(key);
  await login(req, user);
  res.json({ user: pub(user) });
}));

app.get('/vendor/webauthn.js', (req, res) =>
  res.sendFile(path.join(__dirname, 'node_modules/@simplewebauthn/browser/dist/bundle/index.umd.min.js'), { maxAge: '7d' }));

// ── 상담 ──
app.post('/api/consultations', auth(), wrap(async (req, res) => {
  const category = CATEGORIES.includes(req.body.category) ? req.body.category : '기타';
  const title = String(req.body.title || '').trim();
  const body = String(req.body.body || '').trim();
  if (!title || title.length > 120) return res.status(400).json({ error: '제목은 1~120자로 해주세요.' });
  if (!body || body.length > MAX_MSG) return res.status(400).json({ error: `고민 내용은 1~${MAX_MSG}자로 해주세요.` });
  const r = await q('INSERT INTO consultations (client_id, category, title) VALUES (?, ?, ?)', [req.user.id, category, title]);
  await q('INSERT INTO messages (consultation_id, sender_id, body) VALUES (?, ?, ?)', [r.insertId, req.user.id, body]);
  io.to('counselors').emit('queue');
  res.json({ id: r.insertId });
}));

const LIST = `SELECT c.*, cl.nickname AS client_name, co.nickname AS counselor_name
  FROM consultations c JOIN users cl ON cl.id = c.client_id LEFT JOIN users co ON co.id = c.counselor_id`;

app.get('/api/consultations/mine', auth(), wrap(async (req, res) => {
  res.json(await q(`${LIST} WHERE c.client_id = ? OR c.counselor_id = ? ORDER BY c.id DESC`, [req.user.id, req.user.id]));
}));

app.get('/api/consultations/waiting', auth('counselor', 'admin'), wrap(async (req, res) => {
  res.json(await q(`${LIST} WHERE c.status = 'waiting' ORDER BY c.id`));
}));

app.get('/api/consultations/:id', auth(), wrap(async (req, res) => {
  const c = await access(req.user, req.params.id);
  if (!c) return res.status(403).json({ error: '볼 수 없는 상담이에요.' });
  const [info] = await q(`${LIST} WHERE c.id = ?`, [c.id]);
  const messages = await q(
    `SELECT m.id, m.sender_id, m.body, m.created_at, u.nickname, u.role
     FROM messages m JOIN users u ON u.id = m.sender_id WHERE m.consultation_id = ? ORDER BY m.id`, [c.id]);
  res.json({ consultation: info, messages, me: req.user.id });
}));

app.post('/api/consultations/:id/accept', auth('counselor', 'admin'), wrap(async (req, res) => {
  const r = await q("UPDATE consultations SET status = 'active', counselor_id = ? WHERE id = ? AND status = 'waiting' AND client_id <> ?",
    [req.user.id, req.params.id, req.user.id]);
  if (!r.affectedRows) return res.status(409).json({ error: '이미 다른 상담자가 맡았거나 수락할 수 없는 상담이에요.' });
  io.to('counselors').emit('queue');
  io.to('c:' + req.params.id).emit('status', { status: 'active', counselor: req.user.nickname });
  res.json({ ok: true });
}));

app.post('/api/consultations/:id/close', auth(), wrap(async (req, res) => {
  const c = await access(req.user, req.params.id);
  if (!c || (c.status === 'waiting' && c.client_id !== req.user.id && req.user.role !== 'admin'))
    return res.status(403).json({ error: '권한이 없어요.' });
  await q("UPDATE consultations SET status = 'closed', closed_at = NOW() WHERE id = ? AND status <> 'closed'", [c.id]);
  io.to('counselors').emit('queue');
  io.to('c:' + c.id).emit('status', { status: 'closed' });
  res.json({ ok: true });
}));

// ── 상담자 지원 ──
app.post('/api/apply', auth('user'), wrap(async (req, res) => {
  if (req.user.is_anonymous) return res.status(403).json({ error: '회원만 지원할 수 있어요.' });
  const intro = String(req.body.intro || '').trim();
  if (intro.length < 10 || intro.length > 2000) return res.status(400).json({ error: '소개글은 10~2000자로 해주세요.' });
  const [p] = await q("SELECT id FROM counselor_applications WHERE user_id = ? AND status = 'pending'", [req.user.id]);
  if (p) return res.status(409).json({ error: '이미 심사 중인 지원서가 있어요.' });
  await q('INSERT INTO counselor_applications (user_id, intro) VALUES (?, ?)', [req.user.id, intro]);
  res.json({ ok: true });
}));

app.get('/api/apply', auth(), wrap(async (req, res) => {
  res.json(await q('SELECT id, status, created_at, decided_at FROM counselor_applications WHERE user_id = ? ORDER BY id DESC', [req.user.id]));
}));

// ── 관리자 ──
const admin = auth('admin');
app.get('/api/admin/applications', admin, wrap(async (req, res) => {
  res.json(await q(`SELECT a.*, u.nickname, u.email FROM counselor_applications a JOIN users u ON u.id = a.user_id
    ORDER BY a.status = 'pending' DESC, a.id DESC LIMIT 200`));
}));

app.post('/api/admin/applications/:id/:decision', admin, wrap(async (req, res) => {
  if (!['approve', 'reject'].includes(req.params.decision)) return res.status(404).json({ error: '없는 주소예요.' });
  const status = req.params.decision === 'approve' ? 'approved' : 'rejected';
  const [a] = await q("SELECT * FROM counselor_applications WHERE id = ? AND status = 'pending'", [req.params.id]);
  if (!a) return res.status(404).json({ error: '심사할 지원서가 없어요.' });
  await q('UPDATE counselor_applications SET status = ?, decided_at = NOW() WHERE id = ?', [status, a.id]);
  if (status === 'approved') await q("UPDATE users SET role = 'counselor' WHERE id = ? AND role = 'user'", [a.user_id]);
  res.json({ ok: true });
}));

app.get('/api/admin/users', admin, wrap(async (req, res) => {
  res.json(await q('SELECT id, email, nickname, role, is_anonymous, banned, created_at FROM users ORDER BY id DESC LIMIT 500'));
}));

app.post('/api/admin/users/:id', admin, wrap(async (req, res) => {
  if (Number(req.params.id) === req.user.id) return res.status(400).json({ error: '자기 자신은 바꿀 수 없어요.' });
  const { role, banned } = req.body;
  if (role !== undefined) {
    if (!['user', 'counselor', 'admin'].includes(role)) return res.status(400).json({ error: '잘못된 역할' });
    await q('UPDATE users SET role = ? WHERE id = ?', [role, req.params.id]);
  }
  if (banned !== undefined) await q('UPDATE users SET banned = ? WHERE id = ?', [banned ? 1 : 0, req.params.id]);
  res.json({ ok: true });
}));

app.get('/api/admin/consultations', admin, wrap(async (req, res) => {
  res.json(await q(`${LIST} ORDER BY c.id DESC LIMIT 500`));
}));

app.use('/api', (req, res) => res.status(404).json({ error: '없는 주소예요.' }));
app.use(express.static(path.join(__dirname, 'public'), { extensions: ['html'] }));
app.use((err, req, res, next) => {
  console.error(err);
  res.status(500).json({ error: '서버 오류가 났어요.' });
});

// ── 실시간 채팅 ──
const server = http.createServer(app);
const io = new Server(server);
io.engine.use(sessionMw);

io.on('connection', async (socket) => {
  const sess = socket.request.session;
  const me = await sessionUser(sess).catch(() => null);
  if (!me) return socket.disconnect(true);
  if (isStaff(me)) socket.join('counselors');

  socket.on('join', async (id, ack) => {
    const c = await access(me, id).catch(() => null);
    if (c) socket.join('c:' + c.id);
    ack?.({ ok: !!c });
  });

  socket.on('send', async ({ id, body } = {}, ack) => {
    try {
      const u = await getUser(me.id); // 정지·로그아웃 여부 재확인
      const user = sessionOk(u, sess) ? u : null;
      const text = String(body || '').trim();
      const c = user && await access(user, id);
      if (!c || c.status !== 'active' || (c.client_id !== user.id && c.counselor_id !== user.id))
        return ack?.({ error: '메시지를 보낼 수 없어요.' });
      if (!text || text.length > MAX_MSG) return ack?.({ error: `메시지는 1~${MAX_MSG}자로 해주세요.` });
      const r = await q('INSERT INTO messages (consultation_id, sender_id, body) VALUES (?, ?, ?)', [c.id, user.id, text]);
      const [m] = await q(`SELECT m.id, m.sender_id, m.body, m.created_at, u.nickname, u.role
        FROM messages m JOIN users u ON u.id = m.sender_id WHERE m.id = ?`, [r.insertId]);
      io.to('c:' + c.id).emit('msg', m);
      ack?.({ ok: true });
    } catch (e) {
      console.error(e);
      ack?.({ error: '서버 오류가 났어요.' });
    }
  });
});

if (require.main === module) {
  init().then(() => {
    const port = Number(process.env.PORT || 3000);
    server.listen(port, () => console.log(`Love Design on :${port}`));
  }).catch((e) => { console.error(e); process.exit(1); });
}

module.exports = { server, init, pool, store, mail };
