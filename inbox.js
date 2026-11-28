// 문의 메일함 (contact@…): 관리자 페이지에서 IMAP 으로 읽고, SMTP 로 답장한다.
// 요청마다 IMAP 에 붙었다가 끊는다 — 관리자 몇 명이 쓰는 화면이라 연결을 붙잡아 둘 필요가 없다.
const crypto = require('node:crypto');
const nodemailer = require('nodemailer');
const MailComposer = require('nodemailer/lib/mail-composer');
const { ImapFlow } = require('imapflow');
const { simpleParser } = require('mailparser');
const { convert } = require('html-to-text');

const env = process.env;
const USER = env.CONTACT_MAIL_USER;
const PASS = env.CONTACT_MAIL_PASS;
const IMAP_HOST = env.CONTACT_IMAP_HOST || env.SMTP_HOST;
const IMAP_PORT = Number(env.CONTACT_IMAP_PORT || 993);
const SMTP_HOST = env.CONTACT_SMTP_HOST || env.SMTP_HOST;
const SMTP_PORT = Number(env.CONTACT_SMTP_PORT || env.SMTP_PORT || 587);
const FROM = env.CONTACT_MAIL_FROM || (USER && `Love Design <${USER}>`);
const PAGE = 30;

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

// 본문은 텍스트로만 보여준다. HTML 만 있는 메일(첨부가 있으면 mailparser 가 text 를 안 만들어준다)은 직접 바꾼다
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
  return withBox(box, async (client) => {
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
}

async function source(client, uid) {
  const m = await client.fetchOne(String(uid), { source: true, flags: true }, { uid: true });
  if (!m) throw notFound();
  return m;
}

async function get(box, uid) {
  return withBox(box, async (client) => {
    const m = await source(client, uid);
    const p = await simpleParser(m.source);
    if (!m.flags.has('\\Seen')) await client.messageFlagsAdd(String(uid), ['\\Seen'], { uid: true });
    return {
      uid,
      from: addrs(p.from)[0] || null,
      to: addrs(p.to), cc: addrs(p.cc), replyTo: addrs(p.replyTo)[0] || null,
      subject: p.subject || '',
      date: p.date,
      answered: m.flags.has('\\Answered'),
      // HTML 본문은 그리지 않는다 (스크립트·추적 이미지) — mailparser 가 HTML 만 있는 메일도 텍스트로 바꿔준다
      text: bodyText(p),
      attachments: p.attachments.filter((a) => !a.related).map((a, i) => ({ i, filename: a.filename || `첨부${i + 1}`, size: a.size, contentType: a.contentType })),
    };
  });
}

async function attachment(box, uid, i) {
  return withBox(box, async (client) => {
    const p = await simpleParser((await source(client, uid)).source);
    const a = p.attachments.filter((x) => !x.related)[i];
    if (!a) throw notFound();
    return { filename: a.filename || `첨부${i + 1}`, content: a.content };
  });
}

// 보내고, 보낸편지함에도 넣는다 (SMTP 는 사본을 남기지 않으므로)
async function send({ to, subject, text, inReplyTo, references }) {
  const messageId = `<${crypto.randomUUID()}@${USER.split('@')[1]}>`;
  const mail = new MailComposer({ from: FROM, to, subject, text, messageId, inReplyTo, references }).compile();
  const raw = await mail.build();
  await transport.sendMail({ envelope: mail.getEnvelope(), raw });
  const client = await connect().catch(() => null);
  if (client) {
    try {
      const sent = await folderPath(client, 'sent');
      if (sent) await client.append(sent, raw, ['\\Seen']);
    } catch (e) { console.error('imap append', e.message); } finally { await client.logout().catch(() => client.close()); }
  }
  return { messageId };
}

// 받은 메일에 답장: 받는 사람·제목·스레드 헤더를 서버가 원본에서 정한다
async function reply(box, uid, text) {
  const orig = await withBox(box, async (client) => {
    const m = await source(client, uid);
    return simpleParser(m.source);
  });
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
  });
}

module.exports = { enabled, address: USER, list, get, attachment, send, reply, remove };
