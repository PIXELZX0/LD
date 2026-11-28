// 문의 메일함 (contact@…): 관리자 페이지에서 IMAP 으로 읽고, SMTP 로 답장한다.
// 요청마다 IMAP 에 붙었다가 끊는다 — 관리자 몇 명이 쓰는 화면이라 연결을 붙잡아 둘 필요가 없다.
// 받은편지함은 주기적으로 확인해 새 메일 원문을 DB(mail_cache)에 저장해 두고, 화면은 거기서 읽는다.
// 저장본은 받은 지 30일이 지난 '읽은' 메일만 지운다 (안 읽은 메일은 읽을 때까지 둔다). 메일 서버의 메일은 건드리지 않는다.
const crypto = require('node:crypto');
const nodemailer = require('nodemailer');
const MailComposer = require('nodemailer/lib/mail-composer');
const { ImapFlow } = require('imapflow');
const { simpleParser } = require('mailparser');
const { convert } = require('html-to-text');
const { pool } = require('./db');

const env = process.env;
const USER = env.CONTACT_MAIL_USER;
const PASS = env.CONTACT_MAIL_PASS;
const IMAP_HOST = env.CONTACT_IMAP_HOST || env.SMTP_HOST;
const IMAP_PORT = Number(env.CONTACT_IMAP_PORT || 993);
const SMTP_HOST = env.CONTACT_SMTP_HOST || env.SMTP_HOST;
const SMTP_PORT = Number(env.CONTACT_SMTP_PORT || env.SMTP_PORT || 587);
const FROM = env.CONTACT_MAIL_FROM || (USER && `Love Design <${USER}>`);
const PAGE = 30;
const KEEP_DAYS = 30;
const CACHE_MAX = 16 * 1024 * 1024; // 이보다 큰 메일(대개 큰 첨부)은 저장하지 않고 매번 서버에서 받는다
const POLL_MS = Math.max(15, Number(env.CONTACT_POLL_SEC) || 60) * 1000; // 받은편지함 확인 주기
const DAY = 24 * 60 * 60 * 1000;

const enabled = !!(USER && PASS && IMAP_HOST && SMTP_HOST);

const transport = enabled && nodemailer.createTransport({
  host: SMTP_HOST, port: SMTP_PORT, secure: SMTP_PORT === 465, auth: { user: USER, pass: PASS },
});

const notFound = () => Object.assign(new Error('메일을 찾을 수 없어요.'), { status: 404 });

async function connect() {
  const client = new ImapFlow({
    host: IMAP_HOST, port: IMAP_PORT, secure: IMAP_PORT === 993,
    auth: { user: USER, pass: PASS }, logger: false,
    connectionTimeout: 15000, greetingTimeout: 15000, socketTimeout: 60000,
  });
  client.on('error', (e) => console.error('imap', e.message)); // 끊김을 프로세스 오류로 키우지 않는다
  await client.connect();
  return client;
}

// 'inbox' | 'sent' | 'trash' → 실제 폴더 경로 (서버마다 이름이 달라서 special-use 로 찾는다)
async function folderPath(client, box) {
  if (box === 'inbox') return 'INBOX';
  const use = { sent: '\\Sent', trash: '\\Trash' }[box];
  if (!use) return null;
  const list = await client.list();
  const hit = list.find((f) => f.specialUse === use)
    || list.find((f) => new RegExp(box === 'sent' ? '^(sent|보낸)' : '^(trash|deleted|휴지)', 'i').test(f.name));
  return hit?.path || null;
}

async function withBox(box, fn) {
  const client = await connect();
  try {
    const path = await folderPath(client, box);
    if (!path) throw notFound();
    const lock = await client.getMailboxLock(path);
    try { return await fn(client, path); } finally { lock.release(); }
  } finally {
    await client.logout().catch(() => client.close());
  }
}

// ── 원문 캐시 ──
// box 가 inbox 가 아니면(보낸편지함·휴지통) '읽은' 것으로 친다 → 받은 지 30일 지나면 지운다
const isSeen = (box, flags) => (box !== 'inbox' || !!flags?.has('\\Seen') ? 1 : 0);
const recent = (date) => !date || Date.now() - new Date(date).getTime() < KEEP_DAYS * DAY;
const logCache = (e) => console.error('mail cache', e.message);

async function cached(box, uid) {
  try {
    const [[r]] = await pool.query('SELECT source FROM mail_cache WHERE box = ? AND uid = ?', [box, uid]);
    return r?.source || null;
  } catch (e) { logCache(e); return null; } // 캐시가 안 돼도 메일은 읽혀야 한다
}
// received: 메일 서버가 받은 시각(INTERNALDATE). 시간대가 섞이지 않게 MySQL 이 epoch 초에서 바꾼다
async function keep(box, uidValidity, uid, source, { seen = 0, received } = {}) {
  if (!uidValidity || !uid || !source || source.length > CACHE_MAX) return;
  const at = received ? Math.floor(new Date(received).getTime() / 1000) : null;
  await pool.query(`INSERT INTO mail_cache (box, uid, uidvalidity, source, seen, received_at)
    VALUES (?, ?, ?, ?, ?, COALESCE(FROM_UNIXTIME(?), NOW()))
    ON DUPLICATE KEY UPDATE uidvalidity = VALUES(uidvalidity), source = VALUES(source), seen = VALUES(seen),
      received_at = VALUES(received_at), created_at = NOW()`,
  [box, uid, String(uidValidity), source, seen, Number.isFinite(at) ? at : null]).catch(logCache);
}
const markCached = (box, uid) => pool.query('UPDATE mail_cache SET seen = 1 WHERE box = ? AND uid = ?', [box, uid]).catch(logCache);
const forget = (box, uid) => pool.query('DELETE FROM mail_cache WHERE box = ? AND uid = ?', [box, uid]).catch(logCache);
// UIDVALIDITY 가 바뀌면(폴더를 다시 만든 경우 등) 저장해 둔 UID 는 다른 메일을 가리킨다 → 그 메일함 저장본을 비운다
const checkValidity = (box, client) => client.mailbox.uidValidity
  && pool.query('DELETE FROM mail_cache WHERE box = ? AND uidvalidity <> ?', [box, String(client.mailbox.uidValidity)]).catch(logCache);
// 받은 지 30일 지난 읽은 메일의 저장본을 지운다
const purge = () => pool.query(`DELETE FROM mail_cache WHERE seen = 1 AND received_at < NOW() - INTERVAL ${KEEP_DAYS} DAY`)
  .then(([r]) => r.affectedRows);

// 원문: 저장본이 있으면 거기서, 없으면 IMAP 에서 받아 저장한다
async function raw(box, uid) {
  const hit = await cached(box, uid);
  if (hit) return hit;
  return withBox(box, async (client) => {
    const m = await source(client, uid);
    await keep(box, client.mailbox.uidValidity, uid, m.source, { seen: isSeen(box, m.flags), received: m.internalDate });
    return m.source;
  });
}

// 받아 둘 UID 들의 원문을 내려받아 저장한다 (큰 메일은 크기만 먼저 보고 거른다)
async function store(box, client, uids) {
  const small = [];
  for (let i = 0; i < uids.length; i += 200) {
    for await (const m of client.fetch(uids.slice(i, i + 200).join(','), { uid: true, size: true }, { uid: true })) {
      if (m.size <= CACHE_MAX) small.push(m.uid);
    }
  }
  let n = 0;
  for (let i = 0; i < small.length; i += 20) { // source 는 BODY.PEEK[] 라 읽음 표시가 붙지 않는다
    for await (const m of client.fetch(small.slice(i, i + 20).join(','), { uid: true, source: true, flags: true, internalDate: true }, { uid: true })) {
      await keep(box, client.mailbox.uidValidity, m.uid, m.source, { seen: isSeen(box, m.flags), received: m.internalDate });
      n++;
    }
  }
  return n;
}

// 목록에 보인 메일 중 아직 저장 안 한 것을 뒤에서 받아 둔다 (보낸편지함·휴지통용 — 받은편지함은 poll 이 맡는다)
const busy = new Set();
async function prefetch(box, items) {
  const want = items.filter((m) => m.size <= CACHE_MAX && recent(m.date)).map((m) => m.uid); // 오래된 건 받아도 곧 지워진다
  if (!want.length || busy.has(box)) return;
  busy.add(box);
  try {
    const [rows] = await pool.query('SELECT uid FROM mail_cache WHERE box = ? AND uid IN (?)', [box, want]);
    const have = new Set(rows.map((r) => r.uid));
    const need = want.filter((u) => !have.has(u));
    if (need.length) await withBox(box, (client) => store(box, client, need));
  } finally { busy.delete(box); }
}

// 받은편지함 확인: 저장본의 읽음 상태를 서버와 맞추고, 서버에서 없어진 메일의 저장본은 지우고,
// 최근 30일 메일·안 읽은 메일 중 아직 저장 안 한 것(새로 온 메일)을 받아 둔다
async function poll() {
  if (busy.has('inbox')) return 0;
  busy.add('inbox');
  try {
    return await withBox('inbox', async (client) => {
      await checkValidity('inbox', client);
      const [rows] = await pool.query("SELECT uid, seen FROM mail_cache WHERE box = 'inbox'");
      const have = new Map(rows.map((r) => [r.uid, r.seen]));
      if (have.size) {
        const alive = new Set();
        const uids = [...have.keys()];
        for (let i = 0; i < uids.length; i += 500) {
          for await (const m of client.fetch(uids.slice(i, i + 500).join(','), { uid: true, flags: true }, { uid: true })) {
            alive.add(m.uid);
            const seen = isSeen('inbox', m.flags);
            if (seen !== have.get(m.uid)) await pool.query("UPDATE mail_cache SET seen = ? WHERE box = 'inbox' AND uid = ?", [seen, m.uid]);
          }
        }
        const gone = uids.filter((u) => !alive.has(u));
        if (gone.length) await pool.query("DELETE FROM mail_cache WHERE box = 'inbox' AND uid IN (?)", [gone]);
      }
      if (!client.mailbox.exists) return 0;
      const since = new Date(Date.now() - KEEP_DAYS * DAY);
      const found = (await client.search({ or: [{ since }, { seen: false }] }, { uid: true })) || [];
      return store('inbox', client, found.filter((u) => !have.has(u)));
    });
  } finally { busy.delete('inbox'); }
}

// 서버 시작 시 부른다: 받은편지함을 주기적으로 확인하고, 한 시간마다 오래된 읽은 메일 저장본을 지운다
function start() {
  let lastPurge = 0, lastErr = '';
  const tick = async () => {
    if (enabled) {
      try {
        const n = await poll();
        if (n) console.log(`mail: 새 메일 ${n}개 저장`);
        lastErr = '';
      } catch (e) {
        if (e.message !== lastErr) console.error('mail poll', e.message); // 같은 오류를 매분 찍지 않는다
        lastErr = e.message;
      }
    }
    if (Date.now() - lastPurge > 60 * 60 * 1000) {
      lastPurge = Date.now();
      await purge().then((n) => n && console.log(`mail cache: 읽은 지난 메일 ${n}개 정리`)).catch(logCache);
    }
  };
  tick();
  return setInterval(tick, POLL_MS).unref();
}

// 텍스트 본문. HTML 만 있는 메일(첨부가 있으면 mailparser 가 text 를 안 만들어준다)은 직접 바꾼다
const bodyText = (p) => (p.text || (p.html ? convert(p.html, { wordwrap: false, selectors: [{ selector: 'img', format: 'skip' }] }) : ''))
  .replace(/\r\n/g, '\n').trimEnd();

const addr = (a) => a && { name: a.name || '', address: a.address || '' };
const addrs = (v) => (v?.value || []).map(addr);

const summary = (m) => ({
  uid: m.uid,
  from: addr(m.envelope.from?.[0]),
  to: (m.envelope.to || []).map(addr),
  subject: m.envelope.subject || '',
  date: m.envelope.date,
  seen: m.flags.has('\\Seen'),
  answered: m.flags.has('\\Answered'),
  size: m.size,
});
const SUMMARY = { uid: true, flags: true, envelope: true, size: true };

// q 가 있으면 보낸 사람·받는 사람·제목·본문에서 찾는다 (IMAP SEARCH, 한글은 CHARSET UTF-8 로 보낸다)
async function list(box, page = 0, q = '') {
  const r = await withBox(box, async (client) => {
    await checkValidity(box, client);
    const unseen = box === 'inbox' && client.mailbox.exists ? (await client.search({ seen: false }, { uid: true }) || []).length : 0;
    if (q) {
      const uids = ((await client.search({ or: [{ from: q }, { to: q }, { cc: q }, { subject: q }, { body: q }] }, { uid: true })) || [])
        .sort((a, b) => b - a); // UID 가 클수록 나중에 온 메일
      const pick = uids.slice(page * PAGE, (page + 1) * PAGE);
      const items = [];
      if (pick.length) for await (const m of client.fetch(pick.join(','), SUMMARY, { uid: true })) items.push(summary(m));
      items.sort((a, b) => b.uid - a.uid);
      return { total: uids.length, unseen, items, more: uids.length > (page + 1) * PAGE };
    }
    const total = client.mailbox.exists;
    const end = total - page * PAGE;
    const items = [];
    if (end > 0) {
      const start = Math.max(1, end - PAGE + 1);
      for await (const m of client.fetch(`${start}:${end}`, SUMMARY)) {
        items.push(summary(m));
      }
    }
    items.reverse(); // 최신 메일 먼저
    return { total, unseen, items, more: end - PAGE > 0 };
  });
  const bg = box === 'inbox' ? poll() : prefetch(box, r.items); // 열 때 바로 뜨게 뒤에서 받아 둔다
  bg.catch((e) => console.error('mail prefetch', e.message));
  return r;
}

async function source(client, uid) {
  const m = await client.fetchOne(String(uid), { source: true, flags: true, internalDate: true }, { uid: true });
  if (!m) throw notFound();
  return m;
}

// 원격 이미지·배경·글꼴 (추적용으로 흔히 쓰인다). 처음엔 막아 두고 관리자가 누르면 보여준다
const REMOTE = /\b(?:src|srcset|background|poster)\s*=\s*["']?\s*(?:https?:)?\/\/|url\(\s*["']?\s*(?:https?:)?\/\//i;

async function get(box, uid) {
  let src = await cached(box, uid);
  let answered;
  if (src) {
    // 열면 읽음 표시 — 응답을 기다리게 하지 않는다
    markCached(box, uid);
    withBox(box, (client) => client.messageFlagsAdd(String(uid), ['\\Seen'], { uid: true })).catch((e) => console.error('imap seen', e.message));
  } else {
    src = await withBox(box, async (client) => {
      const m = await source(client, uid);
      if (!m.flags.has('\\Seen')) await client.messageFlagsAdd(String(uid), ['\\Seen'], { uid: true });
      answered = m.flags.has('\\Answered');
      await keep(box, client.mailbox.uidValidity, uid, m.source, { seen: 1, received: m.internalDate });
      return m.source;
    });
  }
  const p = await simpleParser(src);
  return {
    uid,
    from: addrs(p.from)[0] || null,
    to: addrs(p.to), cc: addrs(p.cc), replyTo: addrs(p.replyTo)[0] || null,
    subject: p.subject || '',
    date: p.date,
    answered, // 캐시에서 읽으면 모른다 (undefined) — 화면은 목록의 값을 쓴다
    text: bodyText(p),
    html: !!p.html, // HTML 본문은 따로 /html 주소에서 격리해서 보여준다
    remote: !!p.html && REMOTE.test(p.html),
    attachments: p.attachments.filter((a) => !a.related).map((a, i) => ({ i, filename: a.filename || `첨부${i + 1}`, size: a.size, contentType: a.contentType })),
  };
}

// HTML 본문을 그대로 돌려준다. 스크립트·폼·원격 자원 차단은 server.js 의 CSP(sandbox) 가 맡는다.
// cid: 로 붙은 이미지는 mailparser 가 data: 주소로 바꿔준다.
async function html(box, uid) {
  const p = await simpleParser(await raw(box, uid));
  if (!p.html) throw notFound();
  const body = p.html.replace(/<meta[^>]+http-equiv\s*=\s*["']?refresh[^>]*>/gi, ''); // 프레임을 다른 곳으로 보내지 못하게
  return '<!doctype html><meta charset="utf-8"><meta name="referrer" content="no-referrer"><base target="_blank">'
    + '<style>html{color-scheme:light}body{margin:16px;font:15px/1.6 Pretendard,-apple-system,BlinkMacSystemFont,"Apple SD Gothic Neo","Malgun Gothic",sans-serif;color:#161616;background:#fff;overflow-wrap:break-word}img{max-width:100%;height:auto}</style>'
    + body;
}

async function attachment(box, uid, i) {
  const p = await simpleParser(await raw(box, uid));
  const a = p.attachments.filter((x) => !x.related)[i];
  if (!a) throw notFound();
  return { filename: a.filename || `첨부${i + 1}`, content: a.content };
}

// 보내고, 보낸편지함에도 넣는다 (SMTP 는 사본을 남기지 않으므로)
async function send({ to, subject, text, inReplyTo, references }) {
  const messageId = `<${crypto.randomUUID()}@${USER.split('@')[1]}>`;
  const mail = new MailComposer({ from: FROM, to, subject, text, messageId, inReplyTo, references }).compile();
  const msg = await mail.build();
  await transport.sendMail({ envelope: mail.getEnvelope(), raw: msg });
  const client = await connect().catch(() => null);
  if (client) {
    try {
      const sent = await folderPath(client, 'sent');
      const r = sent && await client.append(sent, msg, ['\\Seen']);
      if (r?.uid) await keep('sent', r.uidValidity, r.uid, msg, { seen: 1 });
    } catch (e) { console.error('imap append', e.message); } finally { await client.logout().catch(() => client.close()); }
  }
  return { messageId };
}

// 받은 메일에 답장: 받는 사람·제목·스레드 헤더를 서버가 원본에서 정한다
async function reply(box, uid, text) {
  const orig = await simpleParser(await raw(box, uid));
  const to = orig.replyTo?.value?.[0] || orig.from?.value?.[0];
  if (!to?.address) throw Object.assign(new Error('답장할 주소가 없어요.'), { status: 400 });
  const subject = /^re:/i.test(orig.subject || '') ? orig.subject : `Re: ${orig.subject || ''}`;
  const refs = [].concat(orig.references || [], orig.messageId || []);
  const when = orig.date ? orig.date.toLocaleString('ko-KR', { timeZone: 'Asia/Seoul' }) : '';
  const quoted = bodyText(orig).split('\n').map((l) => '> ' + l).join('\n');
  await send({
    to, subject, inReplyTo: orig.messageId, references: refs,
    text: `${text}\n\n${when}, ${to.name || to.address} 님이 쓴 글:\n${quoted}`,
  });
  await withBox(box, (client) => client.messageFlagsAdd(String(uid), ['\\Answered'], { uid: true })).catch(() => {});
}

// 휴지통으로 옮긴다. 휴지통에서 지우거나 휴지통이 없으면 완전히 지운다.
async function remove(box, uid) {
  return withBox(box, async (client) => {
    const trash = box === 'trash' ? null : await folderPath(client, 'trash');
    const ok = trash ? await client.messageMove(String(uid), trash, { uid: true }) : await client.messageDelete(String(uid), { uid: true });
    if (!ok) throw notFound();
    // 저장해 둔 원문도 따라 옮긴다 (휴지통에서의 새 UID 를 알 때만, 모르면 지운다)
    const to = ok.uidMap?.get(uid);
    if (trash && to && ok.uidValidity) {
      await pool.query(`DELETE FROM mail_cache WHERE box = 'trash' AND uid = ?`, [to]).catch(() => {});
      await pool.query(`UPDATE mail_cache SET box = 'trash', uid = ?, uidvalidity = ?, seen = 1 WHERE box = ? AND uid = ?`, [to, String(ok.uidValidity), box, uid])
        .catch(logCache);
    } else await forget(box, uid);
  });
}

module.exports = { enabled, address: USER, KEEP_DAYS, list, get, html, attachment, send, reply, remove, purge, poll, start };
