// 스모크 테스트: 실제 MySQL 필요 (DATABASE_URL). node --test test.js
process.env.ADMIN_EMAIL ||= 'admin@test.local';
process.env.ADMIN_PASSWORD ||= 'admin-pass-123';
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
  for (const t of ['익명으로 이용하기', '회원으로 이용하기', 'href="/guide"', 'href="/about"', 'href="/login"']) assert.ok(home.includes(t), t);
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
  const form = { email, password: 'password1', nickname: '상담이' };
  assert.equal((await coun('/api/signup', form)).status, 400); // 인증번호 없음
  assert.equal((await coun('/api/signup', { ...form, code: '123456' })).status, 400); // 발송 전
  assert.equal((await coun('/api/email/code', { email })).status, 200);
  assert.equal((await coun('/api/email/code', { email })).status, 429); // 1분 쿨다운
  const code = lastCode(email);
  const wrong = code === '000000' ? '111111' : '000000';
  assert.equal((await coun('/api/signup', { ...form, code: wrong })).status, 400);
  assert.equal((await coun('/api/signup', { ...form, code })).status, 200);
  assert.equal((await coun('/api/email/code', { email })).status, 409); // 이미 가입
  assert.equal((await client()('/api/email/code', { email: process.env.ADMIN_EMAIL })).status, 409);
  assert.equal((await coun('/api/consultations/waiting')).status, 403);
  assert.equal((await coun('/api/apply', { intro: '열 글자 넘는 자기소개입니다' })).status, 200);
  const adm = client();
  assert.equal((await adm('/api/login', { email: process.env.ADMIN_EMAIL, password: process.env.ADMIN_PASSWORD })).status, 200);
  const apps = (await adm('/api/admin/applications')).body;
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
  assert.equal((await me('/api/signup', { email, password: 'password1', nickname: '패스키', code: lastCode(email) })).status, 200);
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
  assert.equal((await me('/api/signup', { email, password: 'password1', nickname: '처음', code: lastCode(email) })).status, 200);
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

  // 다른 기기 모두 로그아웃
  assert.equal((await me('/api/account/logout-others', {})).status, 200);
  assert.equal((await me('/api/me')).body.user?.email, email);
  assert.equal((await again('/api/me')).body.user, null);
  assert.ok((await (await fetch(base + '/account')).text()).includes('내 정보'));
});

test('상담 기록·후기', async () => {
  const adm = client();
  assert.equal((await adm('/api/login', { email: process.env.ADMIN_EMAIL, password: process.env.ADMIN_PASSWORD })).status, 200);
  async function counselor(nickname) {
    const call = client(), email = rnd() + '@t.io';
    await call('/api/email/code', { email });
    assert.equal((await call('/api/signup', { email, password: 'password1', nickname, code: lastCode(email) })).status, 200);
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
