// 스모크 테스트: 실제 MySQL 필요 (DATABASE_URL). node --test test.js
process.env.ADMIN_EMAIL ||= 'admin@test.local';
process.env.ADMIN_PASSWORD ||= 'admin-pass-123';
const test = require('node:test');
const assert = require('node:assert');
const { io: ioc } = require('socket.io-client');
const { server, init, pool, store } = require('./server');

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

test('전체 흐름', async () => {
  const home = await (await fetch(base + '/')).text();
  assert.match(home, /당신에게 맞는<\/em> 사랑을 조각해드립니다/);
  for (const t of ['익명으로 이용하기', '회원으로 이용하기', '이용방법안내', '사이트 소개']) assert.ok(home.includes(t), t);
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
  const coun = client();
  assert.equal((await coun('/api/signup', { email: rnd() + '@t.io', password: 'password1', nickname: '상담이' })).status, 200);
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
