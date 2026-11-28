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
const inbox = require('./inbox');
const xauth = require('./xauth');

const CATEGORIES = ['연애', '인간관계', '진로', '학업', '가족', '직장', '건강', '기타'];
const MAX_MSG = 2000;
const MAX_NOTE = 5000;
const MAX_REVIEW = 1000;
// 약관·개인정보처리방침 시행일 — 문서를 바꾸면 함께 올려서 회원이 어느 판에 동의했는지 남긴다
const TERMS_VER = '2026-11-28';
const MAX_AVATAR = 512 * 1024; // 브라우저에서 줄여 보내므로 보통 수십 KB

const app = express();
app.set('trust proxy', 1);
// 메일 답장·작성은 본문이 길 수 있어서 따로 넉넉하게 받는다
const jsonSmall = express.json({ limit: '20kb' });
const jsonMail = express.json({ limit: '200kb' });
app.use((req, res, next) => (req.path.startsWith('/api/admin/mail') ? jsonMail : jsonSmall)(req, res, next));

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
// 프로필 사진 주소에 내용 해시를 붙여 바뀔 때마다 주소가 달라진다 → 오래 캐시해도 된다
const avatarUrl = (id, hash) => (hash ? `/api/users/${id}/avatar?v=${hash}` : null);
const pub = (x) => x && {
  id: x.id, nickname: x.nickname, role: x.role, is_anonymous: !!x.is_anonymous, email: x.email, avatar: avatarUrl(x.id, x.avatar),
};

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

app.get('/api/me', (req, res) => res.json({ user: pub(req.user), categories: CATEGORIES, social: { x: xauth.enabled } }));

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
  if (!mail.enabled) return res.status(503).json({ error: `지금은 인증 메일을 보낼 수 없어요. ${mail.contact} 로 문의해주세요.` });
  const key = 'mail:' + req.ip;
  if (tooMany(key)) return res.status(429).json({ error: '요청이 너무 많아요. 잠시 후 다시 해주세요.' });
  const [dup] = await q('SELECT id FROM users WHERE email = ?', [email]);
  if (dup) return res.status(409).json({ error: '이미 가입된 이메일이에요.' });
  fail(key);
  await sendCode(res, email, 'signup');
}));

// 인증번호를 만들어 메일로 보낸다 (재발송 1분 간격). 가입용·비밀번호 변경용이 같은 표를 쓴다:
// 가입용은 아직 없는 이메일에만, 비밀번호 변경용은 로그인한 회원 자신의 이메일에만 보내므로 섞이지 않는다.
async function sendCode(res, email, kind) {
  const [prev] = await q('SELECT sent_at > NOW() - INTERVAL 60 SECOND AS recent FROM email_codes WHERE email = ?', [email]);
  if (prev?.recent) return res.status(429).json({ error: '인증번호는 1분에 한 번만 보낼 수 있어요.' });
  const code = String(crypto.randomInt(0, 1_000_000)).padStart(6, '0');
  await q('REPLACE INTO email_codes (email, code_hash, expires_at) VALUES (?, ?, NOW() + INTERVAL 10 MINUTE)', [email, sha(code)]);
  try {
    await mail.send({ to: email, ...mail.verifyCode(code, kind) });
  } catch (e) {
    console.error('mail send failed', e);
    await q('DELETE FROM email_codes WHERE email = ?', [email]);
    return res.status(502).json({ error: '메일을 보내지 못했어요. 주소를 확인하고 다시 시도해주세요.' });
  }
  res.json({ ok: true });
}

// 이메일 인증번호 확인 → 틀리면 오류 문구, 맞으면 null
async function checkCode(email, code) {
  if (!/^\d{6}$/.test(code)) return '이메일로 받은 6자리 인증번호를 입력해주세요.';
  // 시도 횟수를 먼저 원자적으로 올린다 → 동시 요청으로 5회 제한을 넘길 수 없다
  const r0 = await q('UPDATE email_codes SET attempts = attempts + 1 WHERE email = ? AND attempts < 5 AND expires_at > NOW()', [email]);
  if (!r0.affectedRows) return '인증번호가 만료됐어요. 다시 받아주세요.';
  const [ec] = await q('SELECT code_hash FROM email_codes WHERE email = ?', [email]);
  if (!ec || !crypto.timingSafeEqual(Buffer.from(sha(code)), Buffer.from(ec.code_hash))) return '인증번호가 맞지 않아요.';
  return null;
}

app.post('/api/signup', wrap(async (req, res) => {
  const email = normEmail(req.body.email);
  const password = String(req.body.password || '');
  const nickname = String(req.body.nickname || '').trim();
  const code = String(req.body.code || '').trim();
  if (!EMAIL_RE.test(email) || email.length > 190) return res.status(400).json({ error: '이메일 형식을 확인해주세요.' });
  if (password.length < 8 || password.length > 72) return res.status(400).json({ error: '비밀번호는 8~72자로 해주세요.' });
  if (nickname.length < 1 || nickname.length > 20) return res.status(400).json({ error: '닉네임은 1~20자로 해주세요.' });
  if (req.body.agree !== true) return res.status(400).json({ error: '필수 약관에 모두 동의해주세요.' });
  const bad = await checkCode(email, code);
  if (bad) return res.status(400).json({ error: bad });
  try {
    const r = await q('INSERT INTO users (email, password_hash, nickname, terms_ver, agreed_at) VALUES (?, ?, ?, ?, NOW())',
      [email, await bcrypt.hash(password, 10), nickname, TERMS_VER]);
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

// ── 비밀번호 찾기 (로그아웃 상태): 가입한 이메일로 받은 인증번호로 새 비밀번호를 정하고 바로 로그인 ──
// 가입 화면이 이미 '이미 가입된 이메일'을 알려 주므로, 여기서도 가입 여부를 숨기지 않는다
app.post('/api/password/reset/code', wrap(async (req, res) => {
  const email = normEmail(req.body.email);
  if (!EMAIL_RE.test(email) || email.length > 190) return res.status(400).json({ error: '이메일 형식을 확인해주세요.' });
  if (!mail.enabled) return res.status(503).json({ error: `지금은 인증 메일을 보낼 수 없어요. ${mail.contact} 로 문의해주세요.` });
  const key = 'reset:' + req.ip;
  if (tooMany(key)) return res.status(429).json({ error: '요청이 너무 많아요. 잠시 후 다시 해주세요.' });
  const [user] = await q('SELECT banned FROM users WHERE email = ?', [email]);
  if (!user) return res.status(404).json({ error: '가입되지 않은 이메일이에요. X로 가입했다면 X로 로그인해주세요.' });
  if (user.banned) return res.status(403).json({ error: '이용이 정지된 계정이에요.' });
  fail(key);
  await sendCode(res, email, 'reset');
}));

app.post('/api/password/reset', wrap(async (req, res) => {
  const email = normEmail(req.body.email);
  const password = String(req.body.password || '');
  if (password.length < 8 || password.length > 72) return res.status(400).json({ error: '새 비밀번호는 8~72자로 해주세요.' });
  const [row] = await q('SELECT id, banned FROM users WHERE email = ?', [email]);
  if (!row) return res.status(404).json({ error: '가입되지 않은 이메일이에요.' });
  if (row.banned) return res.status(403).json({ error: '이용이 정지된 계정이에요.' });
  const bad = await checkCode(email, String(req.body.code || '').trim());
  if (bad) return res.status(400).json({ error: bad });
  await q('DELETE FROM email_codes WHERE email = ?', [email]);
  // 비밀번호가 새어 나갔을 수 있으니 다른 기기의 로그인은 모두 끊는다
  await q('UPDATE users SET password_hash = ?, session_ver = session_ver + 1 WHERE id = ?', [await bcrypt.hash(password, 10), row.id]);
  const user = await getUser(row.id);
  await login(req, user);
  res.json({ user: pub(user) });
}));

app.post('/api/logout', (req, res) => req.session.destroy(() => res.json({ ok: true })));

// ── X 로그인·가입·계정 연결 ──
// /api/auth/x → X 동의 화면 → /api/auth/x/callback
//   이미 연결된 X 계정이면 그 회원으로 로그인, 처음 보는 계정이면 /signup?via=x 에서 약관 동의·닉네임을 받아 가입
//   ?link=1 (로그인한 회원) 이면 지금 계정에 X 를 연결한다
const X_TTL = 10 * 60 * 1000;
const xRedirect = (req) => process.env.X_REDIRECT_URI || `${req.protocol}://${req.get('host')}/api/auth/x/callback`;
const safeNext = (v) => (typeof v === 'string' && /^\/(?![/\\])/.test(v) ? v : '/my');
const xAccount = async (userId) => (await q("SELECT username, created_at FROM social_accounts WHERE provider = 'x' AND user_id = ?", [userId]))[0] || null;
const xPending = (req) => { const p = req.session.xsignup; return p && p.exp > Date.now() ? p : null; };
const sameStr = (a, b) => typeof a === 'string' && typeof b === 'string' && a.length === b.length && crypto.timingSafeEqual(Buffer.from(a), Buffer.from(b));
const saveSession = (req) => new Promise((ok, no) => req.session.save((e) => (e ? no(e) : ok())));

app.get('/api/auth/x', wrap(async (req, res) => {
  const link = req.query.link === '1';
  if (!xauth.enabled) return res.redirect((link ? '/account' : '/login') + '?xerr=off');
  if (link && (!req.user || req.user.is_anonymous)) return res.redirect('/login?next=%2Faccount');
  const s = xauth.start(xRedirect(req));
  req.session.xauth = { state: s.state, verifier: s.verifier, link: link ? req.user.id : 0, next: safeNext(req.query.next), exp: Date.now() + X_TTL };
  await saveSession(req);
  res.redirect(s.url);
}));

app.get('/api/auth/x/callback', wrap(async (req, res) => {
  const st = req.session.xauth;
  // state 는 한 번만 쓴다: 지운 것을 먼저 저장해 둔다 (응답이 끝날 때의 자동 저장을 기다리면 그 사이에 재사용될 수 있다)
  if (st) { delete req.session.xauth; await saveSession(req); }
  const back = st?.link ? '/account' : '/login';
  const oops = (code, path = back) => res.redirect(`${path}?xerr=${code}`);
  if (!st || st.exp < Date.now() || !sameStr(req.query.state, st.state)) return oops('expired');
  if (req.query.error || typeof req.query.code !== 'string') return oops('denied'); // 사용자가 X 화면에서 취소
  let p;
  try { p = await xauth.profile(req.query.code, st.verifier, xRedirect(req)); } catch (e) {
    console.warn('x login failed', e.message);
    return oops('fail');
  }
  const [linked] = await q("SELECT user_id FROM social_accounts WHERE provider = 'x' AND subject = ?", [p.id]);

  if (st.link) {
    if (!req.user || req.user.id !== st.link) return oops('expired', '/login');
    if (linked) return linked.user_id === req.user.id ? res.redirect('/account?x=linked') : oops('taken');
    try {
      await q("INSERT INTO social_accounts (provider, subject, user_id, username) VALUES ('x', ?, ?, ?)", [p.id, req.user.id, p.username]);
    } catch (e) {
      if (e.code === 'ER_DUP_ENTRY') return oops(await xAccount(req.user.id) ? 'already' : 'taken');
      throw e;
    }
    return res.redirect('/account?x=linked');
  }

  if (linked) {
    const user = await getUser(linked.user_id);
    if (!user) return oops('banned');
    await q("UPDATE social_accounts SET username = ? WHERE provider = 'x' AND subject = ?", [p.username, p.id]); // X 아이디는 바뀔 수 있다
    await login(req, user);
    return res.redirect(st.next);
  }
  // 처음 보는 X 계정: 가입 화면에서 약관 동의·닉네임을 받는다 (X 이름은 닉네임 기본값으로만 쓰고 저장하지 않음)
  req.session.xsignup = { id: p.id, username: p.username, name: p.name, next: st.next, exp: Date.now() + X_TTL };
  await saveSession(req);
  res.redirect('/signup?via=x');
}));

app.get('/api/signup/x', (req, res) => {
  const p = xPending(req);
  res.json({ pending: p ? { username: p.username, name: p.name } : null });
});

app.post('/api/signup/x', wrap(async (req, res) => {
  const p = xPending(req);
  if (!p) return res.status(400).json({ error: '시간이 지났어요. X로 가입하기를 다시 눌러주세요.' });
  const nickname = String(req.body.nickname || '').trim();
  if (nickname.length < 1 || nickname.length > 20) return res.status(400).json({ error: '닉네임은 1~20자로 해주세요.' });
  if (req.body.agree !== true) return res.status(400).json({ error: '필수 약관에 모두 동의해주세요.' });
  const conn = await pool.getConnection();
  let id;
  try {
    await conn.beginTransaction();
    const [r] = await conn.query('INSERT INTO users (nickname, terms_ver, agreed_at) VALUES (?, ?, NOW())', [nickname, TERMS_VER]);
    id = r.insertId;
    await conn.query("INSERT INTO social_accounts (provider, subject, user_id, username) VALUES ('x', ?, ?, ?)", [p.id, id, p.username]);
    await conn.commit();
  } catch (e) {
    await conn.rollback();
    if (e.code === 'ER_DUP_ENTRY') {
      delete req.session.xsignup;
      return res.status(409).json({ error: '이미 가입된 X 계정이에요. X로 로그인해주세요.' });
    }
    throw e;
  } finally { conn.release(); }
  const user = await getUser(id);
  await login(req, user); // 세션을 새로 만들면서 xsignup 도 사라진다
  res.json({ user: pub(user), next: p.next });
}));

// 로그인할 방법이 하나도 남지 않게 되는 변경은 막는다 (이메일+비밀번호 / X / 패스키)
async function loginMethods(user) {
  const [[pk], x] = await Promise.all([q('SELECT COUNT(*) AS n FROM passkeys WHERE user_id = ?', [user.id]), xAccount(user.id)]);
  return { password: !!(user.email && user.password_hash), x: !!x, passkeys: Number(pk.n) };
}

app.post('/api/account/x/unlink', auth(), wrap(async (req, res) => {
  const m = await loginMethods(req.user);
  if (!m.x) return res.status(404).json({ error: '연결된 X 계정이 없어요.' });
  if (!m.password && !m.passkeys)
    return res.status(400).json({ error: 'X 말고는 로그인할 방법이 없어서 연결을 해제할 수 없어요. 먼저 이메일 로그인이나 패스키를 추가해주세요.' });
  await q("DELETE FROM social_accounts WHERE provider = 'x' AND user_id = ?", [req.user.id]);
  res.json({ ok: true });
}));

// X 로 가입한 회원이 이메일 로그인(이메일 인증 + 비밀번호)을 추가한다
app.post('/api/account/email', auth(), wrap(async (req, res) => {
  if (req.user.is_anonymous) return res.status(403).json({ error: '회원만 이메일을 등록할 수 있어요.' });
  if (req.user.email) return res.status(400).json({ error: '이미 이메일이 등록돼 있어요.' });
  const email = normEmail(req.body.email);
  const password = String(req.body.password || '');
  if (!EMAIL_RE.test(email) || email.length > 190) return res.status(400).json({ error: '이메일 형식을 확인해주세요.' });
  if (password.length < 8 || password.length > 72) return res.status(400).json({ error: '비밀번호는 8~72자로 해주세요.' });
  const bad = await checkCode(email, String(req.body.code || '').trim());
  if (bad) return res.status(400).json({ error: bad });
  try {
    const r = await q('UPDATE users SET email = ?, password_hash = ? WHERE id = ? AND email IS NULL',
      [email, await bcrypt.hash(password, 10), req.user.id]);
    if (!r.affectedRows) return res.status(400).json({ error: '이미 이메일이 등록돼 있어요.' });
  } catch (e) {
    if (e.code === 'ER_DUP_ENTRY') return res.status(409).json({ error: '이미 가입된 이메일이에요.' });
    throw e;
  }
  await q('DELETE FROM email_codes WHERE email = ?', [email]);
  res.json({ user: pub({ ...req.user, email }) });
}));

// ── 내 정보 ──
app.get('/api/account', auth(), wrap(async (req, res) => {
  const x = req.user.is_anonymous ? null : await xAccount(req.user.id);
  res.json({ user: { ...pub(req.user), created_at: req.user.created_at, has_password: !!req.user.password_hash, x }, social: { x: xauth.enabled } });
}));

app.post('/api/account/nickname', auth(), wrap(async (req, res) => {
  if (req.user.is_anonymous) return res.status(403).json({ error: '회원만 닉네임을 바꿀 수 있어요.' });
  const nickname = String(req.body.nickname || '').trim();
  if (nickname.length < 1 || nickname.length > 20) return res.status(400).json({ error: '닉네임은 1~20자로 해주세요.' });
  await q('UPDATE users SET nickname = ? WHERE id = ?', [nickname, req.user.id]);
  res.json({ user: pub({ ...req.user, nickname }) });
}));

// ── 프로필 사진 ──
// 형식은 파일 앞부분(매직 바이트)으로만 판단한다. 보낸 Content-Type 은 믿지 않는다.
function imageType(buf) {
  if (buf.length > 3 && buf[0] === 0xff && buf[1] === 0xd8 && buf[2] === 0xff) return 'image/jpeg';
  if (buf.length > 8 && buf.subarray(0, 8).equals(Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]))) return 'image/png';
  if (buf.length > 12 && buf.toString('latin1', 0, 4) === 'RIFF' && buf.toString('latin1', 8, 12) === 'WEBP') return 'image/webp';
  return null;
}

app.post('/api/account/avatar', auth(), express.raw({ type: () => true, limit: MAX_AVATAR }), wrap(async (req, res) => {
  if (req.user.is_anonymous) return res.status(403).json({ error: '회원만 프로필 사진을 정할 수 있어요.' });
  const data = Buffer.isBuffer(req.body) ? req.body : Buffer.alloc(0);
  const mime = imageType(data);
  if (!mime) return res.status(400).json({ error: 'JPG·PNG·WEBP 사진만 올릴 수 있어요.' });
  const hash = sha(data).slice(0, 16);
  await q(`INSERT INTO avatars (user_id, mime, data) VALUES (?, ?, ?)
    ON DUPLICATE KEY UPDATE mime = VALUES(mime), data = VALUES(data), updated_at = NOW()`, [req.user.id, mime, data]);
  await q('UPDATE users SET avatar = ? WHERE id = ?', [hash, req.user.id]);
  res.json({ user: pub({ ...req.user, avatar: hash }) });
}));

app.post('/api/account/avatar/delete', auth(), wrap(async (req, res) => {
  await q('DELETE FROM avatars WHERE user_id = ?', [req.user.id]);
  await q('UPDATE users SET avatar = NULL WHERE id = ?', [req.user.id]);
  res.json({ user: pub({ ...req.user, avatar: null }) });
}));

// 상담 서비스라 사진도 아무에게나 보이지 않는다: 본인·관리자, 그리고 상담에서 마주치는 상대만
async function canSeeAvatar(viewer, ownerId) {
  if (viewer.id === ownerId || viewer.role === 'admin') return true;
  const [row] = await q(`SELECT 1 FROM consultations WHERE (client_id = ? AND counselor_id = ?) OR (counselor_id = ? AND client_id = ?)
    OR (client_id = ? AND status = 'waiting' AND ?) LIMIT 1`,
  [ownerId, viewer.id, ownerId, viewer.id, ownerId, viewer.role === 'counselor' ? 1 : 0]);
  return !!row;
}

app.get('/api/users/:id/avatar', auth(), wrap(async (req, res) => {
  const id = Number(req.params.id);
  const [a] = Number.isInteger(id) && await canSeeAvatar(req.user, id)
    ? await q('SELECT mime, data FROM avatars WHERE user_id = ?', [id]) : [];
  if (!a) return res.status(404).json({ error: '사진이 없어요.' });
  res.set({
    'Content-Type': a.mime,
    'X-Content-Type-Options': 'nosniff',
    'Content-Security-Policy': "default-src 'none'; sandbox",
    'Cache-Control': req.query.v ? 'private, max-age=31536000, immutable' : 'private, no-cache',
  });
  res.send(a.data);
}));

// 다른 기기의 세션은 session_ver 를 올려 끊고, 지금 세션만 새 버전으로 다시 로그인
async function bumpSessions(req) {
  await q('UPDATE users SET session_ver = session_ver + 1 WHERE id = ?', [req.user.id]);
  await login(req, await getUser(req.user.id));
}

// 비밀번호 변경: 현재 비밀번호를 모르면 가입한 이메일로 받은 인증번호나 등록한 패스키로 본인 확인
app.post('/api/account/password/code', auth(), wrap(async (req, res) => {
  if (req.user.is_anonymous || !req.user.email) return res.status(403).json({ error: '이메일로 가입한 회원만 쓸 수 있어요.' });
  if (!mail.enabled) return res.status(503).json({ error: `지금은 인증 메일을 보낼 수 없어요. ${mail.contact} 로 문의해주세요.` });
  const key = 'pwmail:' + req.user.id; // 자기 이메일로만 보내므로 회원별로 센다
  if (tooMany(key)) return res.status(429).json({ error: '요청이 너무 많아요. 잠시 후 다시 해주세요.' });
  fail(key);
  await sendCode(res, req.user.email, 'password');
}));

app.post('/api/account/password', auth(), wrap(async (req, res) => {
  if (req.user.is_anonymous) return res.status(403).json({ error: '회원만 비밀번호를 바꿀 수 있어요.' });
  if (!req.user.email) return res.status(400).json({ error: '먼저 이메일 로그인을 추가해주세요.' });
  const key = 'pw:' + req.user.id;
  if (tooMany(key)) return res.status(429).json({ error: '시도가 너무 많아요. 잠시 후 다시 해주세요.' });
  const password = String(req.body.password || '');
  if (password.length < 8 || password.length > 72) return res.status(400).json({ error: '새 비밀번호는 8~72자로 해주세요.' });
  if (req.body.passkey) {
    const expectedChallenge = takeChallenge(req, 'reauth');
    if (!expectedChallenge) return res.status(400).json({ error: '시간이 지났어요. 다시 시도해주세요.' });
    const pk = await verifyPasskey(req, req.body.passkey, expectedChallenge);
    if (!pk || pk.user_id !== req.user.id) {
      fail(key);
      return res.status(400).json({ error: '이 계정에 등록된 패스키가 아니에요.' });
    }
  } else if (req.body.code !== undefined) {
    const bad = await checkCode(req.user.email, String(req.body.code).trim());
    if (bad) return res.status(400).json({ error: bad });
    await q('DELETE FROM email_codes WHERE email = ?', [req.user.email]);
  } else if (!(await bcrypt.compare(String(req.body.current || ''), req.user.password_hash || ''))) {
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
    userName: req.user.email || (await xAccount(req.user.id).then((x) => x && '@' + x.username)) || req.user.nickname,
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
  const m = await loginMethods(req.user);
  if (!m.password && !m.x && m.passkeys <= 1)
    return res.status(400).json({ error: '마지막 로그인 방법이라 삭제할 수 없어요. 먼저 X 계정을 연결해주세요.' });
  const r = await q('DELETE FROM passkeys WHERE id = ? AND user_id = ?', [String(req.body.id || ''), req.user.id]);
  if (!r.affectedRows) return res.status(404).json({ error: '없는 패스키예요.' });
  res.json({ ok: true });
}));

// 패스키 서명 확인 → 맞으면 그 패스키 행(카운터·마지막 사용 갱신), 아니면 null
async function verifyPasskey(req, response, expectedChallenge) {
  const [pk] = await q('SELECT * FROM passkeys WHERE id = ?', [String(response?.id || '')]);
  if (!pk) return null;
  if (response.response?.userHandle && response.response.userHandle !== b64url(userHandle(pk.user_id))) return null;
  const { rpID, origin } = rp(req);
  let v;
  try {
    v = await webauthn.verifyAuthenticationResponse({
      response, expectedChallenge, expectedOrigin: origin, expectedRPID: rpID, requireUserVerification: true,
      credential: { id: pk.id, publicKey: new Uint8Array(pk.public_key), counter: Number(pk.counter), transports: pk.transports?.split(',') },
    });
  } catch (e) {
    console.warn('passkey verify failed', e.message);
  }
  if (!v?.verified) return null;
  await q('UPDATE passkeys SET counter = ?, last_used_at = NOW() WHERE id = ?', [v.authenticationInfo.newCounter, pk.id]);
  return pk;
}

// 로그인한 회원의 본인 확인용 (비밀번호 변경) → 자기 패스키만 허용
app.post('/api/account/reauth/options', auth(), member, wrap(async (req, res) => {
  const mine = await q('SELECT id, transports FROM passkeys WHERE user_id = ?', [req.user.id]);
  if (!mine.length) return res.status(400).json({ error: '등록한 패스키가 없어요.' });
  const options = await webauthn.generateAuthenticationOptions({
    rpID: rp(req).rpID, userVerification: 'required',
    allowCredentials: mine.map((p) => ({ id: p.id, transports: p.transports ? p.transports.split(',') : undefined })),
  });
  keepChallenge(req, 'reauth', options.challenge);
  res.json(options);
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
  const pk = await verifyPasskey(req, req.body.response, expectedChallenge);
  if (!pk) {
    fail(key);
    return res.status(401).json({ error: '등록되지 않은 패스키예요. 비밀번호로 로그인한 뒤 내 정보에서 등록해주세요.' });
  }
  const user = await getUser(pk.user_id);
  if (!user) return res.status(403).json({ error: '이용이 정지된 계정이에요.' });
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

const withAvatar = (m) => ({ ...m, avatar: avatarUrl(m.sender_id, m.avatar) });

const LIST = `SELECT c.*, cl.nickname AS client_name, co.nickname AS counselor_name, r.rating
  FROM consultations c JOIN users cl ON cl.id = c.client_id LEFT JOIN users co ON co.id = c.counselor_id
  LEFT JOIN reviews r ON r.consultation_id = c.id`;

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
  const messages = (await q(
    `SELECT m.id, m.sender_id, m.body, m.created_at, u.nickname, u.role, u.avatar
     FROM messages m JOIN users u ON u.id = m.sender_id WHERE m.consultation_id = ? ORDER BY m.id`, [c.id])).map(withAvatar);
  // 상담 기록: 담당 상담자·관리자만 / 후기: 내담자·담당 상담자·관리자
  const staffView = req.user.role === 'admin' || (c.counselor_id === req.user.id && isStaff(req.user));
  const [note] = staffView ? await q(`SELECT n.body, n.updated_at, u.nickname AS author
    FROM counselor_notes n LEFT JOIN users u ON u.id = n.author_id WHERE n.consultation_id = ?`, [c.id]) : [];
  const [review] = staffView || c.client_id === req.user.id
    ? await q('SELECT rating, body, created_at, updated_at FROM reviews WHERE consultation_id = ?', [c.id]) : [];
  res.json({
    consultation: info, messages, me: req.user.id,
    note: note || null, review: review || null, can_note: staffView && !!c.counselor_id,
  });
}));

// ── 상담 기록 (상담자 작성, 내담자에겐 보이지 않음) ──
app.post('/api/consultations/:id/note', auth('counselor', 'admin'), wrap(async (req, res) => {
  const [c] = await q('SELECT * FROM consultations WHERE id = ?', [req.params.id]);
  if (!c || !c.counselor_id || (c.counselor_id !== req.user.id && req.user.role !== 'admin'))
    return res.status(403).json({ error: '담당 상담자만 기록을 남길 수 있어요.' });
  const body = String(req.body.body ?? '').trim();
  if (body.length > MAX_NOTE) return res.status(400).json({ error: `상담 기록은 ${MAX_NOTE}자까지 쓸 수 있어요.` });
  if (!body) {
    await q('DELETE FROM counselor_notes WHERE consultation_id = ?', [c.id]);
    return res.json({ note: null });
  }
  await q(`INSERT INTO counselor_notes (consultation_id, author_id, body) VALUES (?, ?, ?)
    ON DUPLICATE KEY UPDATE author_id = VALUES(author_id), body = VALUES(body), updated_at = NOW()`, [c.id, req.user.id, body]);
  const [note] = await q('SELECT body, updated_at FROM counselor_notes WHERE consultation_id = ?', [c.id]);
  res.json({ note: { ...note, author: req.user.nickname } });
}));

// ── 상담 후기 (내담자, 종료된 상담에 1개 — 다시 쓰면 수정) ──
app.post('/api/consultations/:id/review', auth(), wrap(async (req, res) => {
  const [c] = await q('SELECT * FROM consultations WHERE id = ?', [req.params.id]);
  if (!c || c.client_id !== req.user.id) return res.status(403).json({ error: '내 상담에만 후기를 남길 수 있어요.' });
  if (c.status !== 'closed' || !c.counselor_id) return res.status(400).json({ error: '상담자와의 상담이 끝난 뒤에 후기를 남길 수 있어요.' });
  const rating = Number(req.body.rating);
  if (!Number.isInteger(rating) || rating < 1 || rating > 5) return res.status(400).json({ error: '별점을 1~5점 중에서 골라주세요.' });
  const body = String(req.body.body || '').trim();
  if (body.length > MAX_REVIEW) return res.status(400).json({ error: `후기는 ${MAX_REVIEW}자까지 쓸 수 있어요.` });
  await q(`INSERT INTO reviews (consultation_id, client_id, rating, body) VALUES (?, ?, ?, ?)
    ON DUPLICATE KEY UPDATE rating = VALUES(rating), body = VALUES(body), updated_at = NOW()`, [c.id, req.user.id, rating, body || null]);
  const [review] = await q('SELECT rating, body, created_at, updated_at FROM reviews WHERE consultation_id = ?', [c.id]);
  res.json({ review });
}));

// ── 상담 기록 모아보기: 상담자는 내가 맡은 상담, 관리자는 전체 ──
app.get('/api/records', auth('counselor', 'admin'), wrap(async (req, res) => {
  const scope = ['c.counselor_id IS NOT NULL'], sp = [];
  if (req.user.role !== 'admin') { scope.push('c.counselor_id = ?'); sp.push(req.user.id); }
  const where = [...scope], params = [...sp];
  if (req.user.role === 'admin' && req.query.counselor) { where.push('c.counselor_id = ?'); params.push(Number(req.query.counselor) || 0); }
  if (['active', 'closed'].includes(req.query.status)) { where.push('c.status = ?'); params.push(req.query.status); }
  const kw = String(req.query.q || '').trim().slice(0, 50);
  if (kw) {
    const like = '%' + kw.replace(/[\\%_]/g, '\\$&') + '%';
    where.push('(c.title LIKE ? OR cl.nickname LIKE ? OR co.nickname LIKE ? OR n.body LIKE ? OR r.body LIKE ?)');
    params.push(like, like, like, like, like);
  }
  const rows = await q(`SELECT c.id, c.title, c.category, c.status, c.created_at, c.closed_at, c.client_id, c.counselor_id,
      cl.nickname AS client_name, co.nickname AS counselor_name,
      (SELECT COUNT(*) FROM messages m WHERE m.consultation_id = c.id) AS msg_count,
      n.body AS note, n.updated_at AS note_at, nu.nickname AS note_author,
      r.rating, r.body AS review, r.updated_at AS review_at
    FROM consultations c JOIN users cl ON cl.id = c.client_id LEFT JOIN users co ON co.id = c.counselor_id
    LEFT JOIN counselor_notes n ON n.consultation_id = c.id LEFT JOIN users nu ON nu.id = n.author_id
    LEFT JOIN reviews r ON r.consultation_id = c.id
    WHERE ${where.join(' AND ')} ORDER BY c.id DESC LIMIT 300`, params);
  const counselors = await q(`SELECT co.id, co.nickname, COUNT(*) AS total,
      SUM(c.status = 'active') AS active, SUM(c.status = 'closed') AS closed,
      COUNT(r.rating) AS reviews, ROUND(AVG(r.rating), 1) AS avg_rating
    FROM consultations c JOIN users co ON co.id = c.counselor_id LEFT JOIN reviews r ON r.consultation_id = c.id
    WHERE ${scope.join(' AND ')} GROUP BY co.id, co.nickname ORDER BY total DESC`, sp);
  res.json({ rows, counselors: counselors.map((x) => ({ ...x, active: Number(x.active), closed: Number(x.closed),
    avg_rating: x.avg_rating == null ? null : Number(x.avg_rating) })) });
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

// 검색(닉네임·이메일·X 아이디) + 필터: kind=member|guest(익명), role=user|counselor|admin
app.get('/api/admin/users', admin, wrap(async (req, res) => {
  const where = [], args = [];
  const s = String(req.query.q || '').trim().slice(0, 100);
  if (s) {
    const like = '%' + s.replace(/[\\%_]/g, '\\$&') + '%'; // % _ 는 글자 그대로 찾는다
    where.push('(u.nickname LIKE ? OR u.email LIKE ? OR sx.username LIKE ?)'); args.push(like, like, like);
  }
  if (req.query.kind === 'member') where.push('u.is_anonymous = 0');
  else if (req.query.kind === 'guest') where.push('u.is_anonymous = 1');
  if (['user', 'counselor', 'admin'].includes(req.query.role)) { where.push('u.role = ?'); args.push(req.query.role); }
  res.json(await q(`SELECT u.id, u.email, u.nickname, u.role, u.is_anonymous, u.banned, u.created_at, sx.username AS x_username
    FROM users u LEFT JOIN social_accounts sx ON sx.user_id = u.id AND sx.provider = 'x'
    ${where.length ? 'WHERE ' + where.join(' AND ') : ''} ORDER BY u.id DESC LIMIT 500`, args));
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

// ── 문의 메일함 (contact@) ──
const MAX_MAIL = 20000;
const BOXES = ['inbox', 'sent', 'trash'];
const mailbox = (req, res, next) => {
  if (!inbox.enabled) return res.status(503).json({ error: '메일함이 설정되지 않았어요. CONTACT_MAIL_USER / CONTACT_MAIL_PASS 환경변수를 넣어주세요.' });
  if (req.params.box && !BOXES.includes(req.params.box)) return res.status(404).json({ error: '없는 메일함이에요.' });
  if (req.params.uid && !/^\d{1,10}$/.test(req.params.uid)) return res.status(404).json({ error: '메일을 찾을 수 없어요.' });
  next();
};
// IMAP·SMTP 오류를 관리자에게 알아볼 수 있게 돌려준다 (내부 오류 문구는 숨김)
const mailWrap = (fn) => wrap(async (req, res) => {
  try { await fn(req, res); } catch (e) {
    if (e.status) return res.status(e.status).json({ error: e.message });
    console.error('mailbox', e);
    res.status(502).json({ error: e.authenticationFailed ? '메일 서버 로그인에 실패했어요. 계정 설정을 확인해주세요.' : '메일 서버와 통신하지 못했어요. 잠시 후 다시 해주세요.' });
  }
});
const mailText = (v) => String(v ?? '').replace(/\r\n/g, '\n');
const recipients = (v) => String(v || '').split(/[,;\s]+/).map(normEmail).filter(Boolean);

app.get('/api/admin/mail', admin, (req, res) => res.json({ enabled: inbox.enabled, address: inbox.address || null }));
app.get('/api/admin/mail/:box', admin, mailbox, mailWrap(async (req, res) => {
  const page = Math.min(Math.max(parseInt(req.query.page, 10) || 0, 0), 1000);
  const q = String(req.query.q || '').replace(/[\x00-\x1f\x7f]/g, ' ').trim();
  if (q.length > 100) return res.status(400).json({ error: '검색어는 100자까지 넣을 수 있어요.' });
  res.json(await inbox.list(req.params.box, page, q));
}));
app.get('/api/admin/mail/:box/:uid', admin, mailbox, mailWrap(async (req, res) => {
  res.json(await inbox.get(req.params.box, Number(req.params.uid)));
}));
// HTML 본문: 관리자 화면의 iframe 안에서만 그린다. 스크립트·폼·플러그인은 sandbox 로 막고,
// 원격 이미지는 관리자가 '이미지 표시'를 눌렀을 때(images=1)만 허용한다 (열람 추적·IP 노출 방지)
app.get('/api/admin/mail/:box/:uid/html', admin, mailbox, mailWrap(async (req, res) => {
  const doc = await inbox.html(req.params.box, Number(req.params.uid));
  const remote = req.query.images === '1' ? ' https: http:' : '';
  res.type('html').set({
    'X-Content-Type-Options': 'nosniff',
    'Referrer-Policy': 'no-referrer',
    'Cache-Control': 'private, no-store',
    'Content-Security-Policy': `default-src 'none'; img-src data:${remote}; style-src 'unsafe-inline'${remote}; font-src data:${remote}; `
      + "form-action 'none'; frame-ancestors 'self'; sandbox allow-popups allow-popups-to-escape-sandbox",
  }).send(doc);
}));
app.get('/api/admin/mail/:box/:uid/att/:i', admin, mailbox, mailWrap(async (req, res) => {
  const a = await inbox.attachment(req.params.box, Number(req.params.uid), Number(req.params.i) || 0);
  // 메일 첨부는 신뢰할 수 없다 → 브라우저가 열지 않고 내려받게만 한다
  res.attachment(a.filename).type('application/octet-stream')
    .set({ 'X-Content-Type-Options': 'nosniff', 'Content-Security-Policy': "default-src 'none'; sandbox" }).send(a.content);
}));
app.post('/api/admin/mail/send', admin, mailbox, mailWrap(async (req, res) => {
  const to = recipients(req.body.to);
  const subject = String(req.body.subject || '').trim();
  const text = mailText(req.body.body).trimEnd();
  if (!to.length || to.length > 10 || !to.every((x) => EMAIL_RE.test(x) && x.length <= 190)) return res.status(400).json({ error: '받는 사람 이메일을 확인해주세요. (최대 10명, 쉼표로 구분)' });
  if (!subject || subject.length > 200) return res.status(400).json({ error: '제목은 1~200자로 해주세요.' });
  if (!text.trim() || text.length > MAX_MAIL) return res.status(400).json({ error: `본문은 1~${MAX_MAIL}자로 해주세요.` });
  await inbox.send({ to, subject, text });
  res.json({ ok: true });
}));
app.post('/api/admin/mail/:box/:uid/reply', admin, mailbox, mailWrap(async (req, res) => {
  const text = mailText(req.body.body).trimEnd();
  if (!text.trim() || text.length > MAX_MAIL) return res.status(400).json({ error: `답장은 1~${MAX_MAIL}자로 해주세요.` });
  await inbox.reply(req.params.box, Number(req.params.uid), text);
  res.json({ ok: true });
}));
app.post('/api/admin/mail/:box/:uid/delete', admin, mailbox, mailWrap(async (req, res) => {
  await inbox.remove(req.params.box, Number(req.params.uid));
  res.json({ ok: true });
}));

app.use('/api', (req, res) => res.status(404).json({ error: '없는 주소예요.' }));
app.use(express.static(path.join(__dirname, 'public'), { extensions: ['html'] }));
app.use((err, req, res, next) => {
  if (err.type === 'entity.too.large') return res.status(413).json({ error: '보낸 내용이 너무 커요.' });
  if (err.type === 'entity.parse.failed') return res.status(400).json({ error: '요청 형식이 잘못됐어요.' });
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
      const [m] = await q(`SELECT m.id, m.sender_id, m.body, m.created_at, u.nickname, u.role, u.avatar
        FROM messages m JOIN users u ON u.id = m.sender_id WHERE m.id = ?`, [r.insertId]);
      io.to('c:' + c.id).emit('msg', withAvatar(m));
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
    inbox.start(); // 문의 메일함: 받은편지함 주기 확인·저장, 30일 지난 읽은 메일 저장본 정리
  }).catch((e) => { console.error(e); process.exit(1); });
}

module.exports = { server, init, pool, store, mail };
