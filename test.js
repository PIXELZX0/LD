// 스모크 테스트: 실제 MySQL 필요 (DATABASE_URL). node --test test.js
process.env.ADMIN_EMAIL ||= 'admin@test.local';
process.env.ADMIN_PASSWORD ||= 'admin-pass-123';
process.env.X_CLIENT_ID ||= 'x-test-client';
const test = require('node:test');
const assert = require('node:assert');
const { io: ioc } = require('socket.io-client');
const { server, init, pool, store, mail } = require('./server');

const sent = [];
mail.send = async (m) => { sent.push(m); };
const lastCode = (to) => sent.filter((m) => m.to === to).at(-1).text.match(/\d{6}/)[0];

let base;
test.before(async () => {
  await init();
  await new Promise((r) => server.listen(0, r));
  base = 'http://127.0.0.1:' + server.address().port;
});
test.after(async () => { server.close(); await store.close(); await pool.end(); });

function client() {
  let cookie = '';
  const call = async (path, body) => {
    const r = await fetch(base + path, {
      method: body === undefined ? 'GET' : 'POST',
      headers: { 'Content-Type': 'application/json', cookie },
      body: body === undefined ? undefined : JSON.stringify(body),
    });
    const sc = r.headers.get('set-cookie'); if (sc) cookie = sc.split(';')[0];
    return { status: r.status, body: await r.json().catch(() => null) };
  };
  call.cookie = () => cookie;
  // 리다이렉트를 따라가지 않는 GET → { status, location }
  call.go = async (path) => {
    const r = await fetch(base + path, { headers: { cookie }, redirect: 'manual' });
    const sc = r.headers.get('set-cookie'); if (sc) cookie = sc.split(';')[0];
    return { status: r.status, location: r.headers.get('location') };
  };
  return call;
}
const rnd = () => Math.random().toString(36).slice(2, 8);

// ── 소프트웨어 패스키 (ES256, attestation none) ──
const crypto = require('node:crypto');
function cbor(v) {
  const head = (major, n) => n < 24 ? Buffer.from([major << 5 | n]) : n < 256 ? Buffer.from([major << 5 | 24, n])
    : Buffer.from([major << 5 | 25, n >> 8, n & 255]);
  if (typeof v === 'number') return v >= 0 ? head(0, v) : head(1, -1 - v);
  if (typeof v === 'string') return Buffer.concat([head(3, Buffer.byteLength(v)), Buffer.from(v)]);
  if (Buffer.isBuffer(v)) return Buffer.concat([head(2, v.length), v]);
  const entries = v instanceof Map ? [...v] : Object.entries(v);
  return Buffer.concat([head(5, entries.length), ...entries.flatMap(([k, x]) => [cbor(k), cbor(x)])]);
}
function softPasskey(origin) {
  const rpIdHash = crypto.createHash('sha256').update(new URL(origin).hostname).digest();
  const { privateKey, publicKey } = crypto.generateKeyPairSync('ec', { namedCurve: 'P-256' });
  const jwk = publicKey.export({ format: 'jwk' });
  const id = crypto.randomBytes(16);
  let count = 0, userHandle;
  const client = (type, challenge) => Buffer.from(JSON.stringify({ type, challenge, origin, crossOrigin: false }));
  const u32 = (n) => { const b = Buffer.alloc(4); b.writeUInt32BE(n); return b; };
  return {
    id: id.toString('base64url'),
    create(opts) {
      userHandle = opts.user.id;
      const cose = cbor(new Map([[1, 2], [3, -7], [-1, 1], [-2, Buffer.from(jwk.x, 'base64url')], [-3, Buffer.from(jwk.y, 'base64url')]]));
      const authData = Buffer.concat([rpIdHash, Buffer.from([0x45]), u32(count), Buffer.alloc(16), Buffer.from([0, id.length]), id, cose]);
      return { id: id.toString('base64url'), rawId: id.toString('base64url'), type: 'public-key', clientExtensionResults: {},
        response: { clientDataJSON: client('webauthn.create', opts.challenge).toString('base64url'),
          attestationObject: cbor({ fmt: 'none', attStmt: {}, authData }).toString('base64url'), transports: ['internal'] } };
    },
    get(opts) {
      const authData = Buffer.concat([rpIdHash, Buffer.from([0x05]), u32(++count)]);
      const cd = client('webauthn.get', opts.challenge);
      const signature = crypto.sign('sha256', Buffer.concat([authData, crypto.createHash('sha256').update(cd).digest()]), privateKey);
      return { id: id.toString('base64url'), rawId: id.toString('base64url'), type: 'public-key', clientExtensionResults: {},
        response: { clientDataJSON: cd.toString('base64url'), authenticatorData: authData.toString('base64url'),
          signature: signature.toString('base64url'), userHandle } };
    },
  };
}

test('전체 흐름', async () => {
  const home = await (await fetch(base + '/')).text();
  assert.match(home, /당신에게 맞는<\/em> 사랑을 조각해드립니다/);
  for (const t of ['익명으로 이용하기', '회원으로 이용하기', 'href="/guide"', 'href="/about"', 'href="/login"', 'href="/terms"', 'href="/privacy"', 'href="/counsel"']) assert.ok(home.includes(t), t);
  for (const [page, t] of [['/counsel', '자살예방상담전화'], ['/terms', '이용약관'], ['/privacy', '국외 이전'], ['/signup', '개인정보 수집·이용 동의']])
    assert.ok((await (await fetch(base + page)).text()).includes(t), page);
  assert.equal((await fetch(base + '/healthz')).status, 200);

  // 익명 유저 → 상담 요청
  const anon = client();
  const a = await anon('/api/anon', {});
  assert.equal(a.status, 200); assert.ok(a.body.user.is_anonymous);
  assert.equal((await anon('/api/apply', { intro: '익명은 지원 불가해야 함' })).status, 403);
  const c = await anon('/api/consultations', { category: '연애', title: '고민', body: '첫 메시지' });
  assert.equal(c.status, 200);
  const cid = c.body.id;

  // 회원 → 상담자 지원 → 관리자 승인
  // 이메일 인증
  const coun = client();
  const email = rnd() + '@t.io';
  const form = { email, password: 'password1', nickname: '상담이', agree: true };
  assert.equal((await coun('/api/signup', form)).status, 400); // 인증번호 없음
  assert.equal((await coun('/api/signup', { ...form, code: '123456' })).status, 400); // 발송 전
  assert.equal((await coun('/api/email/code', { email })).status, 200);
  assert.equal((await coun('/api/email/code', { email })).status, 429); // 1분 쿨다운
  const code = lastCode(email);
  const wrong = code === '000000' ? '111111' : '000000';
  assert.equal((await coun('/api/signup', { ...form, code: wrong })).status, 400);
  assert.equal((await coun('/api/signup', { ...form, code, agree: false })).status, 400); // 약관 미동의
  assert.equal((await coun('/api/signup', { ...form, code })).status, 200);
  const [agreed] = (await pool.query('SELECT terms_ver, agreed_at FROM users WHERE email = ?', [email]))[0];
  assert.ok(agreed.terms_ver && agreed.agreed_at, '약관 동의 시각이 남아야 함');
  assert.equal((await coun('/api/email/code', { email })).status, 409); // 이미 가입
  assert.equal((await client()('/api/email/code', { email: process.env.ADMIN_EMAIL })).status, 409);
  assert.equal((await coun('/api/consultations/waiting')).status, 403);
  assert.equal((await coun('/api/apply', { intro: '열 글자 넘는 자기소개입니다' })).status, 200);
  const adm = client();
  assert.equal((await adm('/api/login', { email: process.env.ADMIN_EMAIL, password: process.env.ADMIN_PASSWORD })).status, 200);
  const apps = (await adm('/api/admin/applications')).body;
  // 문의 메일함: 관리자만, 계정 env 가 없으면 503 (CI 에는 메일 서버가 없다)
  assert.equal((await coun('/api/admin/mail/inbox')).status, 403);
  assert.equal((await adm('/api/admin/mail')).body.enabled, false);
  assert.equal((await adm('/api/admin/mail/inbox')).status, 503);
  assert.equal((await adm('/api/admin/mail/send', { to: 'a@b.co', subject: 's', body: 'b' })).status, 503);
  // 회원 검색·필터
  const found = (await adm('/api/admin/users?q=' + encodeURIComponent(email))).body;
  assert.equal(found.length, 1); assert.equal(found[0].email, email);
  assert.ok((await adm('/api/admin/users?role=admin')).body.every((x) => x.role === 'admin'));
  assert.ok((await adm('/api/admin/users?kind=guest')).body.every((x) => x.is_anonymous));
  assert.ok((await adm('/api/admin/users?kind=member&role=user')).body.every((x) => !x.is_anonymous && x.role === 'user'));
  assert.equal((await adm('/api/admin/users?q=%25%25%25' + Date.now())).body.length, 0); // % 는 와일드카드가 아니다
  assert.equal((await coun('/api/admin/users')).status, 403);
  const mine = apps.find((x) => x.nickname === '상담이' && x.status === 'pending');
  assert.equal((await adm(`/api/admin/applications/${mine.id}/approve`, {})).status, 200);
  assert.equal((await coun('/api/me')).body.user.role, 'counselor');

  // 수락 + 중복 수락 거부
  assert.equal((await coun(`/api/consultations/${cid}/accept`, {})).status, 200);
  assert.equal((await adm(`/api/consultations/${cid}/accept`, {})).status, 409);

  // 제3자 열람 거부
  const other = client();
  await other('/api/anon', {});
  assert.equal((await other(`/api/consultations/${cid}`)).status, 403);

  // 실시간 채팅
  const sock = (call) => ioc(base, { extraHeaders: { cookie: call.cookie() }, transports: ['websocket'] });
  const s1 = sock(anon), s2 = sock(coun), s3 = sock(other);
  const join = (s) => new Promise((r) => s.emit('join', cid, r));
  assert.ok((await join(s1)).ok); assert.ok((await join(s2)).ok); assert.ok(!(await join(s3)).ok);
  const got = new Promise((r) => s1.on('msg', r));
  const ack = await new Promise((r) => s2.emit('send', { id: cid, body: '안녕하세요' }, r));
  assert.ok(ack.ok);
  assert.equal((await got).body, '안녕하세요');
  const bad = await new Promise((r) => s3.emit('send', { id: cid, body: '침입' }, r));
  assert.ok(bad.error);

  // 종료 후 전송 불가
  assert.equal((await anon(`/api/consultations/${cid}/close`, {})).status, 200);
  const late = await new Promise((r) => s1.emit('send', { id: cid, body: '늦음' }, r));
  assert.ok(late.error);
  const detail = (await anon(`/api/consultations/${cid}`)).body;
  assert.deepEqual(detail.messages.map((m) => m.body), ['첫 메시지', '안녕하세요']);
  [s1, s2, s3].forEach((s) => s.close());
});

test('패스키', async () => {
  const email = rnd() + '@t.io';
  const me = client();
  await me('/api/email/code', { email });
  assert.equal((await me('/api/signup', { email, password: 'password1', nickname: '패스키', code: lastCode(email), agree: true })).status, 200);
  const key = softPasskey(base);

  // 익명·비로그인은 등록 불가
  const anon = client(); await anon('/api/anon', {});
  assert.equal((await anon('/api/passkey/register/options', {})).status, 403);
  assert.equal((await client()('/api/passkey/register/options', {})).status, 401);

  // 등록: 챌린지 없이 검증하면 거부, 정상 등록, 같은 응답 재사용 거부
  assert.equal((await me('/api/passkey/register/verify', { response: {} })).status, 400);
  const ro = (await me('/api/passkey/register/options', {})).body;
  assert.equal(ro.authenticatorSelection.residentKey, 'required');
  const created = key.create(ro);
  assert.equal((await me('/api/passkey/register/verify', { response: created })).status, 200);
  assert.equal((await me('/api/passkey/register/verify', { response: created })).status, 400);
  const list = (await me('/api/passkeys')).body;
  assert.equal(list.length, 1); assert.equal(list[0].id, key.id);
  const ro2 = (await me('/api/passkey/register/options', {})).body;
  assert.deepEqual(ro2.excludeCredentials.map((c) => c.id), [key.id]);

  // 로그인: 새 브라우저에서 이메일 없이
  const fresh = client();
  const lo = (await fresh('/api/passkey/login/options', {})).body;
  const asserted = key.get(lo);
  const ok = await fresh('/api/passkey/login/verify', { response: asserted });
  assert.equal(ok.status, 200); assert.equal(ok.body.user.nickname, '패스키');
  assert.equal((await fresh('/api/me')).body.user.nickname, '패스키');
  // 같은 서명 재사용(리플레이) 거부
  const replay = client();
  await replay('/api/passkey/login/options', {});
  assert.equal((await replay('/api/passkey/login/verify', { response: asserted })).status, 401);
  // 모르는 패스키 거부
  const stranger = client();
  const so = (await stranger('/api/passkey/login/options', {})).body;
  const other = softPasskey(base); other.create({ user: { id: 'eA' }, challenge: 'x' });
  assert.equal((await stranger('/api/passkey/login/verify', { response: other.get(so) })).status, 401);

  // 현재 비밀번호를 몰라도 내 패스키로 본인 확인하고 바꿀 수 있다 (남의 패스키·챌린지 없이는 거부)
  assert.equal((await anon('/api/account/reauth/options', {})).status, 403);
  assert.equal((await me('/api/account/password', { passkey: key.get({ challenge: 'x' }), password: 'password2' })).status, 400);
  const so2 = (await me('/api/account/reauth/options', {})).body;
  assert.deepEqual(so2.allowCredentials.map((c) => c.id), [key.id]);
  assert.equal((await me('/api/account/password', { passkey: other.get(so2), password: 'password2' })).status, 400);
  const ra = (await me('/api/account/reauth/options', {})).body;
  assert.equal((await me('/api/account/password', { passkey: key.get(ra), password: 'password2' })).status, 200);
  assert.equal((await client()('/api/login', { email, password: 'password2' })).status, 200);

  // 남의 패스키는 못 지우고, 내 것은 지우면 더 이상 로그인 불가
  assert.equal((await anon('/api/passkeys/delete', { id: key.id })).status, 403);
  assert.equal((await me('/api/passkeys/delete', { id: key.id })).status, 200);
  const after = client();
  const ao = (await after('/api/passkey/login/options', {})).body;
  assert.equal((await after('/api/passkey/login/verify', { response: key.get(ao) })).status, 401);
  assert.equal((await fetch(base + '/vendor/webauthn.js')).status, 200);
});

test('내 정보', async () => {
  const email = rnd() + '@t.io';
  const me = client();
  await me('/api/email/code', { email });
  assert.equal((await me('/api/signup', { email, password: 'password1', nickname: '처음', code: lastCode(email), agree: true })).status, 200);
  const other = client(); // 같은 계정의 다른 기기
  assert.equal((await other('/api/login', { email, password: 'password1' })).status, 200);

  const acc = (await me('/api/account')).body.user;
  assert.equal(acc.email, email); assert.ok(acc.created_at);
  assert.equal((await client()('/api/account')).status, 401);

  // 닉네임
  assert.equal((await me('/api/account/nickname', { nickname: '' })).status, 400);
  assert.equal((await me('/api/account/nickname', { nickname: '바뀜' })).status, 200);
  assert.equal((await me('/api/me')).body.user.nickname, '바뀜');
  const anon = client(); await anon('/api/anon', {});
  assert.equal((await anon('/api/account')).status, 200);
  assert.equal((await anon('/api/account/nickname', { nickname: '익명아님' })).status, 403);
  assert.equal((await anon('/api/account/password', { current: '', password: 'password2' })).status, 403);

  // 비밀번호: 현재 비밀번호 틀림 → 거부, 바꾸면 다른 기기 로그아웃·지금 기기 유지
  assert.equal((await me('/api/account/password', { current: 'nope', password: 'password2' })).status, 400);
  assert.equal((await me('/api/account/password', { current: 'password1', password: 'short' })).status, 400);
  assert.equal((await me('/api/account/password', { current: 'password1', password: 'password2' })).status, 200);
  assert.equal((await me('/api/me')).body.user?.email, email);
  assert.equal((await other('/api/me')).body.user, null);
  assert.equal((await client()('/api/login', { email, password: 'password1' })).status, 401);
  const again = client();
  assert.equal((await again('/api/login', { email, password: 'password2' })).status, 200);

  // 현재 비밀번호를 몰라도 가입한 이메일로 받은 인증번호로 바꿀 수 있다
  assert.equal((await anon('/api/account/password/code', {})).status, 403);
  assert.equal((await again('/api/account/password/code', {})).status, 200);
  assert.match(sent.at(-1).subject, /비밀번호 변경/);
  assert.equal((await again('/api/account/password/code', {})).status, 429); // 1분 쿨다운
  assert.equal((await again('/api/account/password', { code: '000000', password: 'password3' })).status, 400);
  assert.equal((await again('/api/account/password', { code: lastCode(email), password: 'password3' })).status, 200);
  assert.equal((await again('/api/account/password', { code: lastCode(email), password: 'password4' })).status, 400); // 한 번만
  assert.equal((await me('/api/me')).body.user, null); // 다른 기기 로그아웃
  assert.equal((await me('/api/login', { email, password: 'password3' })).status, 200);

  // 다른 기기 모두 로그아웃
  assert.equal((await me('/api/account/logout-others', {})).status, 200);
  assert.equal((await me('/api/me')).body.user?.email, email);
  assert.equal((await again('/api/me')).body.user, null);
  assert.ok((await (await fetch(base + '/account')).text()).includes('내 정보'));

  // 비밀번호 찾기 (로그아웃 상태): 가입한 이메일로 인증번호 → 새 비밀번호 + 바로 로그인, 다른 기기는 로그아웃
  assert.ok((await (await fetch(base + '/reset')).text()).includes('비밀번호 찾기'));
  assert.ok((await (await fetch(base + '/login')).text()).includes('href="/reset"'));
  const lost = client();
  assert.equal((await lost('/api/password/reset/code', { email: 'nobody-' + rnd() + '@t.io' })).status, 404);
  assert.equal((await lost('/api/password/reset/code', { email: email.toUpperCase() })).status, 200);
  assert.match(sent.at(-1).subject, /비밀번호 찾기/);
  assert.equal((await lost('/api/password/reset/code', { email })).status, 429); // 1분 쿨다운
  assert.equal((await lost('/api/password/reset', { email, code: '000000', password: 'password5' })).status, 400);
  assert.equal((await lost('/api/password/reset', { email, code: lastCode(email), password: 'short' })).status, 400);
  const code = lastCode(email);
  assert.equal((await lost('/api/password/reset', { email, code, password: 'password5' })).status, 200);
  assert.equal((await lost('/api/me')).body.user?.email, email);
  assert.equal((await me('/api/me')).body.user, null);
  assert.equal((await client()('/api/password/reset', { email, code, password: 'password6' })).status, 400); // 한 번만
  assert.equal((await client()('/api/login', { email, password: 'password5' })).status, 200);
});

test('상담 기록·후기', async () => {
  const adm = client();
  assert.equal((await adm('/api/login', { email: process.env.ADMIN_EMAIL, password: process.env.ADMIN_PASSWORD })).status, 200);
  async function counselor(nickname) {
    const call = client(), email = rnd() + '@t.io';
    await call('/api/email/code', { email });
    assert.equal((await call('/api/signup', { email, password: 'password1', nickname, code: lastCode(email), agree: true })).status, 200);
    await call('/api/apply', { intro: '열 글자 넘는 자기소개입니다' });
    const app = (await adm('/api/admin/applications')).body.find((x) => x.email === email);
    assert.equal((await adm(`/api/admin/applications/${app.id}/approve`, {})).status, 200);
    return call;
  }
  const co = await counselor('기록이'), co2 = await counselor('남상담');
  const cl = client(); await cl('/api/anon', {});
  const cid = (await cl('/api/consultations', { category: '진로', title: '진로 고민', body: '어떻게 할까요' })).body.id;

  // 배정 전에는 아무도 기록 못 씀, 후기도 못 씀
  assert.equal((await co(`/api/consultations/${cid}/note`, { body: '메모' })).status, 403);
  assert.equal((await adm(`/api/consultations/${cid}/note`, { body: '메모' })).status, 403);
  assert.equal((await cl(`/api/consultations/${cid}/review`, { rating: 5 })).status, 400);
  assert.equal((await co(`/api/consultations/${cid}/accept`, {})).status, 200);

  // 상담 기록: 담당 상담자만, 내담자·다른 상담자 거부
  assert.equal((await cl(`/api/consultations/${cid}/note`, { body: '메모' })).status, 403);
  assert.equal((await co2(`/api/consultations/${cid}/note`, { body: '메모' })).status, 403);
  assert.equal((await co(`/api/consultations/${cid}/note`, { body: 'x'.repeat(5001) })).status, 400);
  const saved = await co(`/api/consultations/${cid}/note`, { body: '  진로 불안, 다음엔 적성 이야기  ' });
  assert.equal(saved.status, 200); assert.equal(saved.body.note.body, '진로 불안, 다음엔 적성 이야기');
  let d = (await co(`/api/consultations/${cid}`)).body;
  assert.equal(d.note.body, '진로 불안, 다음엔 적성 이야기'); assert.equal(d.note.author, '기록이'); assert.ok(d.can_note);
  d = (await cl(`/api/consultations/${cid}`)).body;
  assert.equal(d.note, null); assert.ok(!d.can_note); // 내담자에겐 안 보임
  assert.equal((await adm(`/api/consultations/${cid}`)).body.note.body, '진로 불안, 다음엔 적성 이야기');

  // 후기: 종료 전 거부 → 종료 후 내담자만, 다시 쓰면 수정
  assert.equal((await cl(`/api/consultations/${cid}/review`, { rating: 5 })).status, 400);
  assert.equal((await cl(`/api/consultations/${cid}/close`, {})).status, 200);
  assert.equal((await co(`/api/consultations/${cid}/review`, { rating: 5 })).status, 403);
  assert.equal((await cl(`/api/consultations/${cid}/review`, { rating: 0 })).status, 400);
  assert.equal((await cl(`/api/consultations/${cid}/review`, { rating: 4.5 })).status, 400);
  assert.equal((await cl(`/api/consultations/${cid}/review`, { rating: 3, body: '그럭저럭' })).status, 200);
  const rv = await cl(`/api/consultations/${cid}/review`, { rating: 5, body: '큰 도움이 됐어요' });
  assert.equal(rv.status, 200); assert.equal(rv.body.review.rating, 5);
  assert.equal((await cl(`/api/consultations/${cid}`)).body.review.body, '큰 도움이 됐어요');
  assert.equal((await co(`/api/consultations/${cid}`)).body.review.rating, 5);
  assert.equal((await cl('/api/consultations/mine')).body.find((x) => x.id === cid).rating, 5);
  // 종료 뒤에도 기록은 고칠 수 있음
  assert.equal((await co(`/api/consultations/${cid}/note`, { body: '종결. 적성검사 권유' })).status, 200);

  // 상담 기록 모아보기: 상담자는 내 것만, 관리자는 전체 + 상담자 필터
  assert.equal((await cl('/api/records')).status, 403);
  const mine = (await co('/api/records')).body;
  assert.deepEqual(mine.rows.map((r) => r.id), [cid]);
  assert.equal(mine.rows[0].counselor_name, '기록이');
  assert.equal(mine.rows[0].note, '종결. 적성검사 권유');
  assert.equal(mine.rows[0].review, '큰 도움이 됐어요');
  assert.equal(mine.rows[0].msg_count, 1);
  assert.deepEqual(mine.counselors.map((x) => [x.nickname, x.total, x.closed, x.reviews, x.avg_rating]), [['기록이', 1, 1, 1, 5]]);
  assert.equal((await co2('/api/records')).body.rows.length, 0);
  const all = (await adm('/api/records')).body;
  assert.ok(all.rows.some((r) => r.id === cid));
  const byId = mine.rows[0].counselor_id;
  const filtered = (await adm('/api/records?counselor=' + byId)).body.rows;
  assert.ok(filtered.length && filtered.every((r) => r.counselor_id === byId));
  assert.ok((await adm('/api/records?q=' + encodeURIComponent('적성검사'))).body.rows.some((r) => r.id === cid));
  assert.equal((await adm('/api/records?q=' + encodeURIComponent('100%_없음'))).body.rows.length, 0);
  assert.equal((await co('/api/records?status=active')).body.rows.length, 0);
  // 내용을 비우면 기록 삭제
  assert.equal((await co(`/api/consultations/${cid}/note`, { body: '' })).body.note, null);
  assert.equal((await co(`/api/consultations/${cid}`)).body.note, null);
  assert.ok((await (await fetch(base + '/records')).text()).includes('상담 기록'));
});

test('프로필 사진', async () => {
  const email = rnd() + '@t.io';
  const me = client();
  await me('/api/email/code', { email });
  assert.equal((await me('/api/signup', { email, password: 'password1', nickname: '사진', code: lastCode(email), agree: true })).status, 200);
  const { id } = (await me('/api/me')).body.user;
  assert.equal((await me('/api/me')).body.user.avatar, null);
  const raw = (call, path, body, type) => fetch(base + path, {
    method: body === undefined ? 'GET' : 'POST', headers: { cookie: call.cookie(), ...(type && { 'Content-Type': type }) }, body,
  });

  // 형식은 파일 내용으로 판단: 이미지 아닌 것·너무 큰 것은 거부
  assert.equal((await raw(me, '/api/account/avatar', '<svg onload=alert(1)>', 'image/jpeg')).status, 400);
  assert.equal((await raw(me, '/api/account/avatar', Buffer.alloc(600 * 1024, 0xff), 'image/jpeg')).status, 413);
  const jpg = Buffer.concat([Buffer.from([0xff, 0xd8, 0xff, 0xe0]), crypto.randomBytes(64)]);
  const up = await raw(me, '/api/account/avatar', jpg, 'image/jpeg');
  assert.equal(up.status, 200);
  const url = (await up.json()).user.avatar;
  assert.match(url, new RegExp(`^/api/users/${id}/avatar\\?v=[0-9a-f]{16}$`));
  assert.equal((await me('/api/me')).body.user.avatar, url);
  const got = await raw(me, url);
  assert.equal(got.status, 200);
  assert.equal(got.headers.get('content-type'), 'image/jpeg');
  assert.equal(got.headers.get('x-content-type-options'), 'nosniff');
  assert.ok(Buffer.from(await got.arrayBuffer()).equals(jpg));

  // 상담에서 마주치지 않은 사람·비로그인에게는 안 보인다
  const stranger = client(); await stranger('/api/anon', {});
  assert.equal((await raw(stranger, url)).status, 404);
  assert.equal((await fetch(base + url)).status, 401);
  const adm = client();
  await adm('/api/login', { email: process.env.ADMIN_EMAIL, password: process.env.ADMIN_PASSWORD });
  assert.equal((await raw(adm, url)).status, 200);

  // 상담을 맡은 상담자에게는 보이고, 메시지에도 사진 주소가 실린다
  const { id: cid } = (await me('/api/consultations', { category: '연애', title: '사진 테스트', body: '안녕하세요' })).body;
  assert.equal((await adm(`/api/consultations/${cid}/accept`, {})).status, 200);
  const msgs = (await adm(`/api/consultations/${cid}`)).body.messages;
  assert.equal(msgs[0].avatar, url);

  // 익명은 사진을 정할 수 없다
  const anon = client(); await anon('/api/anon', {});
  assert.equal((await raw(anon, '/api/account/avatar', jpg, 'image/jpeg')).status, 403);

  // 삭제
  assert.equal((await me('/api/account/avatar/delete', {})).body.user.avatar, null);
  assert.equal((await raw(me, url)).status, 404);
  assert.equal((await me('/api/me')).body.user.avatar, null);
});

// ── X 로그인: X API 는 가짜로 바꿔 끼운다 ──
const xauth = require('./xauth');
const xCalls = [];
let xUser;
xauth.http = async (u, opts = {}) => {
  const json = (status, body) => new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } });
  const form = opts.body instanceof URLSearchParams ? opts.body : null;
  xCalls.push({ url: u, form });
  if (u.endsWith('/oauth2/token')) return form.get('code') === 'good' ? json(200, { access_token: 'tok-' + xUser.id }) : json(400, { error: 'invalid_request' });
  if (u.endsWith('/users/me')) return json(200, { data: xUser });
  if (u.endsWith('/oauth2/revoke')) return json(200, { revoked: true });
  return json(404, {});
};
// X 동의 화면까지 가서 state 를 받고, X 가 돌려보내는 콜백을 흉내 낸다 → 콜백이 보낸 곳
async function viaX(c, user, start = '/api/auth/x', code = 'good') {
  xUser = user;
  const r = await c.go(start);
  assert.equal(r.status, 302);
  const to = new URL(r.location, base);
  if (to.origin === base) return r.location; // X 로 가지 않고 끝남 (권한 없음 등)
  assert.equal(to.origin + to.pathname, 'https://x.com/i/oauth2/authorize');
  assert.equal(to.searchParams.get('code_challenge_method'), 'S256');
  const challenge = to.searchParams.get('code_challenge');
  const n = xCalls.length;
  const loc = (await c.go(`/api/auth/x/callback?code=${code}&state=${to.searchParams.get('state')}`)).location;
  const tok = xCalls.slice(n).find((x) => x.url.endsWith('/oauth2/token'));
  if (tok) assert.equal(crypto.createHash('sha256').update(tok.form.get('code_verifier')).digest('base64url'), challenge); // PKCE
  return loc;
}

test('X 로그인·가입·연결', async () => {
  assert.equal((await client()('/api/me')).body.social.x, true);
  const xa = { id: String(Date.now()) + '1', username: 'x_' + rnd(), name: '엑스 사용자 이름이 아주 길어서 스무 자를 넘어요' };

  // 처음 보는 X 계정 → 가입 화면으로, 약관 동의 없이는 가입 불가
  const me = client();
  assert.equal(await viaX(me, xa), '/signup?via=x');
  assert.equal(xCalls.at(-1).url.endsWith('/oauth2/revoke'), true); // 토큰은 바로 폐기
  assert.deepEqual((await me('/api/signup/x')).body.pending, { username: xa.username, name: xa.name });
  assert.equal((await client()('/api/signup/x')).body.pending, null);
  assert.equal((await client()('/api/signup/x', { nickname: '남', agree: true })).status, 400);
  assert.equal((await me('/api/signup/x', { nickname: '엑스', agree: false })).status, 400);
  assert.equal((await me('/api/signup/x', { nickname: '', agree: true })).status, 400);
  // 같은 X 계정으로 두 곳에서 동시에 가입하면 하나만 된다
  const twin = client();
  assert.equal(await viaX(twin, xa), '/signup?via=x');
  const su = await me('/api/signup/x', { nickname: '엑스', agree: true });
  assert.equal(su.status, 200); assert.equal(su.body.user.email, null); assert.equal(su.body.next, '/my');
  assert.equal((await twin('/api/signup/x', { nickname: '쌍둥이', agree: true })).status, 409);
  assert.equal((await me('/api/me')).body.user.nickname, '엑스');
  const acc = (await me('/api/account')).body.user;
  assert.equal(acc.has_password, false); assert.equal(acc.x.username, xa.username);

  // 다시 X 로그인하면 바로 그 회원 (next 는 같은 사이트 경로만)
  const again = client();
  assert.equal(await viaX(again, xa, '/api/auth/x?next=%2Fnew'), '/new');
  assert.equal((await again('/api/me')).body.user.id, su.body.user.id);
  assert.equal(await viaX(client(), xa, '/api/auth/x?next=%2F%2Fevil.example'), '/my');

  // state 가 없거나 다르거나 다시 쓰면 거부, X 에서 취소·토큰 실패
  const s1 = client();
  const st = new URL((await s1.go('/api/auth/x')).location).searchParams.get('state');
  assert.equal((await s1.go('/api/auth/x/callback?code=good&state=wrong')).location, '/login?xerr=expired');
  assert.equal((await s1.go(`/api/auth/x/callback?code=good&state=${st}`)).location, '/login?xerr=expired'); // 이미 지워짐
  assert.equal((await client().go('/api/auth/x/callback?code=good&state=x')).location, '/login?xerr=expired');
  const s2 = client();
  const st2 = new URL((await s2.go('/api/auth/x')).location).searchParams.get('state');
  assert.equal((await s2.go(`/api/auth/x/callback?error=access_denied&state=${st2}`)).location, '/login?xerr=denied');
  assert.equal(await viaX(client(), xa, '/api/auth/x', 'bad'), '/login?xerr=fail');

  // X 로만 로그인하는 회원: 마지막 로그인 방법은 끊을 수 없다 → 패스키를 등록하면 해제 가능
  assert.equal((await me('/api/account/x/unlink', {})).status, 400);
  const key = softPasskey(base);
  const ro = (await me('/api/passkey/register/options', {})).body;
  assert.equal(ro.user.name, '@' + xa.username);
  assert.equal((await me('/api/passkey/register/verify', { response: key.create(ro) })).status, 200);
  assert.equal((await me('/api/account/x/unlink', {})).status, 200);
  assert.equal((await me('/api/account')).body.user.x, null);
  assert.equal((await me('/api/account/x/unlink', {})).status, 404);
  assert.equal((await me('/api/passkeys/delete', { id: key.id })).status, 400); // 마지막 패스키
  // 해제한 X 로 로그인하면 새 가입으로 이어진다 → 다시 연결
  assert.equal(await viaX(client(), xa), '/signup?via=x');
  assert.equal(await viaX(me, xa, '/api/auth/x?link=1'), '/account?x=linked');
  assert.equal(await viaX(me, xa, '/api/auth/x?link=1'), '/account?x=linked'); // 이미 내 것
  assert.equal((await me('/api/passkeys/delete', { id: key.id })).status, 200);

  // X 로 가입한 회원이 이메일 로그인 추가 → 이메일로 로그인 가능
  const mine = rnd() + '@t.io';
  const taken = rnd() + '@t.io';
  const first = client();
  await first('/api/email/code', { email: taken });
  assert.equal((await first('/api/signup', { email: taken, password: 'password1', nickname: '먼저', code: lastCode(taken), agree: true })).status, 200);
  assert.equal((await me('/api/email/code', { email: taken })).status, 409); // 이미 가입된 이메일
  assert.equal((await me('/api/account/x/unlink', {})).status, 400); // 아직 X 뿐
  await me('/api/email/code', { email: mine });
  assert.equal((await me('/api/account/email', { email: mine, code: '000000', password: 'password1' })).status, 400);
  assert.equal((await me('/api/account/email', { email: mine, code: lastCode(mine), password: 'short' })).status, 400);
  const added = await me('/api/account/email', { email: mine, code: lastCode(mine), password: 'password1' });
  assert.equal(added.status, 200); assert.equal(added.body.user.email, mine);
  const acc2 = (await me('/api/account')).body.user;
  assert.equal(acc2.email, mine); assert.equal(acc2.has_password, true);
  assert.equal((await me('/api/account/email', { email: rnd() + '@t.io', code: '123456', password: 'password1' })).status, 400); // 이미 있음
  const byMail = client();
  assert.equal((await byMail('/api/login', { email: mine, password: 'password1' })).status, 200);
  assert.equal((await byMail('/api/me')).body.user.id, su.body.user.id);
  const guest = client(); await guest('/api/anon', {});
  assert.equal((await guest('/api/account/email', { email: rnd() + '@t.io', code: '123456', password: 'password1' })).status, 403);

  // 이메일 회원에 X 연결 → X 로 로그인 가능
  const email = rnd() + '@t.io';
  const em = client();
  await em('/api/email/code', { email });
  assert.equal((await em('/api/signup', { email, password: 'password1', nickname: '메일', code: lastCode(email), agree: true })).status, 200);
  assert.equal(await viaX(em, xa, '/api/auth/x?link=1'), '/account?xerr=taken'); // 남의 X
  const xb = { id: String(Date.now()) + '2', username: 'x_' + rnd(), name: 'B' };
  assert.equal(await viaX(em, xb, '/api/auth/x?link=1'), '/account?x=linked');
  const xc = { id: String(Date.now()) + '3', username: 'x_' + rnd(), name: 'C' };
  assert.equal(await viaX(em, xc, '/api/auth/x?link=1'), '/account?xerr=already'); // 회원당 X 하나
  assert.equal((await em('/api/account')).body.user.has_password, true);
  const byX = client();
  assert.equal(await viaX(byX, { ...xb, username: xb.username + '_new' }), '/my');
  assert.equal((await byX('/api/me')).body.user.email, email);
  assert.equal((await em('/api/account')).body.user.x.username, xb.username + '_new'); // 바뀐 X 아이디 반영
  assert.equal((await em('/api/account/x/unlink', {})).status, 200); // 비밀번호가 있으니 해제 가능

  // 비로그인·익명은 연결 불가, 관리자 회원 검색에 X 아이디
  assert.equal(await viaX(client(), xc, '/api/auth/x?link=1'), '/login?next=%2Faccount');
  const anon = client(); await anon('/api/anon', {});
  assert.equal(await viaX(anon, xc, '/api/auth/x?link=1'), '/login?next=%2Faccount');
  const adm = client();
  await adm('/api/login', { email: process.env.ADMIN_EMAIL, password: process.env.ADMIN_PASSWORD });
  const found = (await adm('/api/admin/users?q=' + encodeURIComponent(xa.username))).body;
  assert.equal(found.length, 1); assert.equal(found[0].x_username, xa.username);

  // 정지된 회원은 X 로도 로그인 불가
  assert.equal((await adm('/api/admin/users/' + su.body.user.id, { banned: true })).status, 200);
  assert.equal(await viaX(client(), xa), '/login?xerr=banned');
  for (const page of ['/login', '/signup', '/account']) assert.ok((await (await fetch(base + page)).text()).includes('<script src="/app.js">'), page);
});
