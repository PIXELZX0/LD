// 화면 테마: 고른 게 없으면 기기 설정을 따른다(top.css 의 prefers-color-scheme).
// app.js 는 모든 페이지 <head> 에서 바로 읽히므로 그리기 전에 붙어 깜빡이지 않는다.
const THEMES = ['system', 'light', 'dark'];
function getTheme() {
  try { const t = localStorage.getItem('theme'); return THEMES.includes(t) ? t : 'system'; } catch { return 'system'; }
}
function applyTheme(t) {
  const root = document.documentElement;
  if (t === 'light' || t === 'dark') root.dataset.theme = t; else delete root.dataset.theme;
  document.querySelectorAll('.theme-pick button').forEach((b) => b.setAttribute('aria-pressed', String(b.value === t)));
  document.querySelectorAll('.theme-btn').forEach((b) => paintThemeButton(b, t));
}
function setTheme(t) {
  try { if (t === 'system') localStorage.removeItem('theme'); else localStorage.setItem('theme', t); } catch {}
  applyTheme(t);
}
applyTheme(getTheme());
// 다른 탭에서 바꾸면 이 탭도 따라간다
window.addEventListener('storage', (e) => { if (e.key === 'theme' || e.key === null) applyTheme(getTheme()); });
// 바닥글의 시스템 · 라이트 · 다크 고르기
function themePicker() {
  const cur = getTheme();
  const b = (v, text) => el('button', { type: 'button', value: v, 'aria-pressed': String(cur === v), onclick: () => setTheme(v) }, text);
  return el('div', { class: 'theme-pick', role: 'group', 'aria-label': '화면 테마' }, b('system', '시스템'), b('light', '라이트'), b('dark', '다크'));
}
// 상단바 테마 버튼: 누를 때마다 시스템 → 라이트 → 다크, 아이콘이 지금 테마를 보여준다
const THEME_NAME = { system: '시스템', light: '라이트', dark: '다크' };
const svgIcon = (d) => `<svg viewBox="0 0 24 24" width="18" height="18" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">${d}</svg>`;
const THEME_ICON = { // 고정된 아이콘 문자열만 innerHTML 로 넣는다
  system: svgIcon('<rect x="3" y="4" width="18" height="12" rx="2"/><path d="M8 20h8M12 16v4"/>'),
  light: svgIcon('<circle cx="12" cy="12" r="4"/><path d="M12 2v2M12 20v2M4.9 4.9l1.4 1.4M17.7 17.7l1.4 1.4M2 12h2M20 12h2M4.9 19.1l1.4-1.4M17.7 6.3l1.4-1.4"/>'),
  dark: svgIcon('<path d="M20 14.5A8 8 0 0 1 9.5 4 8 8 0 1 0 20 14.5z"/>'),
};
const nextTheme = (t) => THEMES[(THEMES.indexOf(t) + 1) % THEMES.length];
function paintThemeButton(b, t) {
  b.innerHTML = THEME_ICON[t];
  const label = `화면 테마: ${THEME_NAME[t]} (누르면 ${THEME_NAME[nextTheme(t)]})`;
  b.setAttribute('aria-label', label); b.title = label;
}
function themeButton() {
  const b = el('button', { type: 'button', class: 'theme-btn', onclick: () => setTheme(nextTheme(getTheme())) });
  paintThemeButton(b, getTheme());
  return b;
}

// 공통 헬퍼
async function api(path, body) {
  const r = await fetch(path, body === undefined ? {} : {
    method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body),
  });
  const data = await r.json().catch(() => ({}));
  if (!r.ok) throw Object.assign(new Error(data.error || '오류가 났어요.'), { status: r.status });
  return data;
}

function el(tag, attrs, ...kids) {
  const e = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs || {})) {
    if (k.startsWith('on')) e.addEventListener(k.slice(2), v);
    else if (v !== false && v != null) e.setAttribute(k, v);
  }
  for (const k of kids.flat()) if (k != null) e.append(k); // 문자열은 텍스트 노드로 → XSS 안전
  return e;
}

const STATUS = { waiting: '대기중', active: '상담중', closed: '종료' };
const ROLE = { user: '일반', counselor: '상담사', admin: '관리자' };
const statusTag = (s) => el('span', { class: 'tag ' + s }, STATUS[s]);
// 별점 표시 (읽기 전용)
const stars = (n) => el('span', { class: 'rate', 'aria-label': `별점 ${n}점` }, '★'.repeat(n), el('i', {}, '★'.repeat(5 - n)));

// 프로필 사진 (없거나 못 불러오면 닉네임 첫 글자)
function avatar(u, size = 28) {
  const initial = () => el('span', { class: 'avatar', style: `--size:${size}px`, 'aria-hidden': 'true' }, [...(u.nickname || '?')][0]);
  if (!u.avatar) return initial();
  const img = el('img', { class: 'avatar', style: `--size:${size}px`, src: u.avatar, alt: '', width: size, height: size, decoding: 'async' });
  img.addEventListener('error', () => img.replaceWith(initial()), { once: true });
  return img;
}
const whoName = (u) => u.nickname + (u.is_anonymous && !u.nickname.startsWith('익명') ? ' (익명)' : '') + '님';
const isStaffRole = (u) => u.role === 'counselor' || u.role === 'admin';
// 로그아웃하면 이 기기의 푸시 구독도 끊는다 (같은 기기를 쓰는 다른 사람에게 알림이 가지 않게)
async function logout(e) { e?.preventDefault(); await disablePush(); await api('/api/logout', {}); location.href = '/'; }

// 상단바 프로필 메뉴: 마우스를 올리면 열리고, 터치·키보드는 눌러서 연다
function meMenu(user) {
  const item = (href, text) => el('a', { class: 'item', href, role: 'menuitem' }, text);
  const btn = el('button', { type: 'button', class: 'who-chip', 'aria-haspopup': 'menu', 'aria-expanded': 'false', 'aria-label': `${whoName(user)} 메뉴` },
    avatar(user, 28), el('span', { class: 'who-name' }, whoName(user)), el('span', { class: 'caret', 'aria-hidden': 'true' }));
  const pop = el('div', { class: 'me-pop', role: 'menu' },
    el('div', { class: 'me-head' }, el('b', {}, user.nickname),
      el('span', {}, user.is_anonymous ? '익명으로 이용 중' : (user.email || ROLE[user.role]))),
    item('/account', '내 정보'), item('/my', '내 상담'),
    user.is_anonymous ? item('/signup', '회원가입') : null,
    el('button', { type: 'button', class: 'item out', role: 'menuitem', onclick: logout }, '로그아웃'));
  const box = el('div', { class: 'me-menu' }, btn, pop);
  let byHover = false, timer = 0;
  const set = (open) => { clearTimeout(timer); box.classList.toggle('open', open); btn.setAttribute('aria-expanded', String(open)); if (!open) byHover = false; };
  box.addEventListener('pointerenter', (e) => { if (e.pointerType === 'mouse' && !box.classList.contains('open')) { byHover = true; set(true); } else clearTimeout(timer); });
  box.addEventListener('pointerleave', (e) => { if (e.pointerType === 'mouse' && byHover) timer = setTimeout(() => set(false), 180); });
  // 마우스로 이미 열린 상태에서 누르면 닫지 않고 고정한다
  btn.addEventListener('click', () => { if (byHover) { byHover = false; return; } set(!box.classList.contains('open')); });
  document.addEventListener('click', (e) => { if (box.isConnected && !box.contains(e.target)) set(false); });
  box.addEventListener('keydown', (e) => {
    const items = [...pop.querySelectorAll('.item')];
    if (e.key === 'Escape') { set(false); btn.focus(); }
    else if (e.key === 'ArrowDown' || e.key === 'ArrowUp') {
      e.preventDefault(); set(true);
      const i = items.indexOf(document.activeElement);
      items[e.key === 'ArrowDown' ? (i + 1) % items.length : (i <= 0 ? items.length : i) - 1]?.focus();
    }
  });
  box.addEventListener('focusout', (e) => { if (!box.contains(e.relatedTarget)) set(false); });
  return box;
}
// ── 실시간 연결: 한 페이지에 소켓 하나 (알림·채팅·대기열이 함께 쓴다) ──
let sockP;
function liveSocket() {
  return (sockP ||= new Promise((ok, no) => {
    if (window.io) return ok(window.io());
    const s = document.createElement('script');
    s.src = '/socket.io/socket.io.js';
    s.onload = () => ok(window.io());
    s.onerror = () => { sockP = null; no(new Error('socket')); };
    document.head.append(s);
  }));
}

// ── 알림 (상단바 종) ──
const BELL_ICON = svgIcon('<path d="M6 8a6 6 0 0 1 12 0c0 7 3 9 3 9H3s3-2 3-9"/><path d="M10.3 21a1.94 1.94 0 0 0 3.4 0"/>');
const SHARE_ICON = svgIcon('<path d="M12 3v12M8 7l4-4 4 4"/><path d="M6 11H5a1 1 0 0 0-1 1v8a1 1 0 0 0 1 1h14a1 1 0 0 0 1-1v-8a1 1 0 0 0-1-1h-1"/>');
const notes = { items: [], unread: 0, at: 0, started: false, push: null, pushOn: false, guest: false };

// 기기 알림이 될 수 있는 환경
const isIOS = () => /iPad|iPhone|iPod/.test(navigator.userAgent) || (navigator.platform === 'MacIntel' && navigator.maxTouchPoints > 1);
const standalone = () => matchMedia('(display-mode: standalone)').matches || navigator.standalone === true;
const canPush = () => !!notes.push && 'serviceWorker' in navigator && 'PushManager' in window && 'Notification' in window;
// 아이폰·아이패드는 홈 화면에 추가한 앱에서만 웹 푸시가 된다 (iOS 16.4+)
const needsInstall = () => isIOS() && !standalone();
const osOn = () => { try { return localStorage.getItem('osNotify') !== 'off'; } catch { return true; } };

// 웹 푸시를 못 쓰는 브라우저: 페이지가 열려 있는 동안만, 다른 탭을 볼 때 브라우저 알림
function osNotify(item) {
  if (notes.pushOn || !('Notification' in window) || Notification.permission !== 'granted' || !osOn() || !document.hidden) return;
  try {
    const n = new Notification('Love Design', { body: item.brief || '새 알림이 있어요.', tag: 'ld-' + item.id, icon: '/icon-192.png' });
    n.onclick = () => { window.focus(); n.close(); location.href = item.link; };
  } catch {} // 모바일 크롬 등은 페이지에서 바로 띄우는 알림을 막는다
}

// ── 웹 푸시 (사이트를 닫아 둬도 이 기기로) ──
let swReg = null;
const b64bytes = (s) => Uint8Array.from(atob(s.replace(/-/g, '+').replace(/_/g, '/') + '='.repeat((4 - s.length % 4) % 4)), (c) => c.charCodeAt(0));
async function pushReg() {
  if (!swReg) { await navigator.serviceWorker.register('/sw.js'); swReg = await navigator.serviceWorker.ready; }
  return swReg;
}
// 페이지를 열 때마다: 이 기기가 구독 중이면 서버에 다시 알려 둔다 (다시 로그인·다른 회원 로그인 뒤에도 지금 회원으로 맞춘다)
async function syncPush() {
  if (!canPush()) return;
  try {
    const sub = await (await pushReg()).pushManager.getSubscription();
    notes.pushOn = !!sub && Notification.permission === 'granted';
    if (notes.pushOn) await api('/api/push/subscribe', sub.toJSON());
  } catch { notes.pushOn = false; }
  paintNotes();
}
// 버튼을 누른 그 자리에서 subscribe 를 불러야 한다 (사파리는 사용자 동작 없이는 권한을 묻지 않는다)
async function enablePush() {
  try {
    const reg = swReg || await pushReg();
    const sub = await reg.pushManager.subscribe({ userVisibleOnly: true, applicationServerKey: b64bytes(notes.push) });
    await api('/api/push/subscribe', sub.toJSON());
    notes.pushOn = true;
  } catch (x) {
    if (Notification.permission !== 'denied') alert(x.status ? x.message : '알림을 켜지 못했어요. 잠시 후 다시 해주세요.');
  }
  paintNotes();
}
async function disablePush() {
  try {
    const reg = swReg || ('serviceWorker' in navigator ? await navigator.serviceWorker.getRegistration() : null);
    const sub = reg && await reg.pushManager.getSubscription();
    if (sub) { await api('/api/push/unsubscribe', { endpoint: sub.endpoint }).catch(() => {}); await sub.unsubscribe(); }
  } catch {}
  notes.pushOn = false;
  paintNotes();
}

function ago(sec) {
  if (sec < 60) return '방금';
  if (sec < 3600) return Math.floor(sec / 60) + '분 전';
  if (sec < 86400) return Math.floor(sec / 3600) + '시간 전';
  if (sec < 86400 * 7) return Math.floor(sec / 86400) + '일 전';
  return '';
}
async function loadNotes() {
  try {
    const r = await api('/api/notifications');
    Object.assign(notes, { items: r.items, unread: r.unread, push: r.push, at: Date.now() });
  } catch { return; }
  paintNotes();
}
async function readNote(body) {
  await api('/api/notifications/read', body).catch(() => {});
}
function paintNotes() {
  const t = document.title.replace(/^\(\d+\+?\) /, '');
  document.title = notes.unread ? `(${notes.unread > 99 ? '99+' : notes.unread}) ${t}` : t;
  document.querySelectorAll('.noti').forEach((box) => {
    const btn = box.querySelector('.bell-btn'), badge = box.querySelector('.badge');
    badge.textContent = notes.unread > 99 ? '99+' : String(notes.unread);
    badge.hidden = !notes.unread;
    const label = notes.unread ? `알림 (안 읽은 알림 ${notes.unread}개)` : '알림';
    btn.setAttribute('aria-label', label); btn.title = label;
    if (box.classList.contains('open')) box.querySelector('.noti-pop').replaceChildren(...notePanel());
  });
  document.dispatchEvent(new Event('notes'));
}
function notePanel() {
  const passed = Math.floor((Date.now() - notes.at) / 1000);
  const item = (x) => el('a', { class: 'noti-item' + (x.read ? '' : ' unread'), href: x.link, onclick: async (e) => {
    e.preventDefault();
    if (!x.read) await readNote({ id: x.id });
    location.href = x.link;
  } }, el('span', { class: 'dot', 'aria-hidden': 'true' }), el('span', { class: 'txt' }, x.text,
    el('span', { class: 'when' }, ago(x.age + passed) || fmt(x.at), x.read ? null : el('span', { class: 'sr' }, ' · 안 읽음'))));
  return [
    el('div', { class: 'noti-head' }, el('b', {}, '알림'),
      el('button', { type: 'button', class: 'linkish', disabled: !notes.unread, onclick: () => readNote({ all: true }).then(loadNotes) }, '모두 읽음')),
    notes.items.length ? el('div', { class: 'noti-list' }, notes.items.map(item)) : el('p', { class: 'noti-empty' }, '아직 알림이 없어요.'),
    osControl(),
  ];
}
// 알림이 켜져 있는지 (켜져 있으면 '알림 켜기' 안내를 다시 보여 주지 않는다)
const deviceNotesOn = () => notes.pushOn || (!canPush() && !needsInstall() && 'Notification' in window && Notification.permission === 'granted' && osOn());

// 종 창 아래: 이 기기로 알림 받기
function osControl() {
  const foot = (...k) => el('div', { class: 'noti-foot' }, ...k);
  const link = (text, onclick) => el('button', { type: 'button', class: 'linkish', onclick }, text);
  const denied = () => foot('이 기기에서 알림이 차단돼 있어요. ', isIOS() ? '설정 앱 > 알림 > Love Design 에서 허용할 수 있어요.' : '주소창 옆 사이트 설정에서 허용할 수 있어요.');
  if (canPush()) {
    if (Notification.permission === 'denied') return denied();
    if (notes.pushOn) return foot('이 기기로 알림을 받고 있어요 · ', link('끄기', disablePush));
    return foot(el('button', { type: 'button', class: 'btn-push', onclick: enablePush }, '이 기기로 알림 받기'),
      el('span', {}, '사이트를 닫아 둬도 상담사 배정·새 메시지를 알려 드려요. 켜면 이 기기의 알림 수신 주소를 저장하고, 알림은 브라우저의 푸시 서비스(구글·애플 등, 미국)를 거쳐 암호화돼 전달돼요. ',
        el('a', { href: '/privacy#push' }, '자세히')));
  }
  if (needsInstall()) {
    return foot(el('button', { type: 'button', class: 'btn-push', onclick: installGuide }, '홈 화면에 추가하고 알림 받기'),
      el('span', {}, '아이폰·아이패드는 홈 화면에 추가한 뒤에 알림을 받을 수 있어요.'));
  }
  if (isIOS()) return foot('알림을 받으려면 iOS 16.4 이상으로 업데이트해 주세요.');
  if (!('Notification' in window)) return null;
  // 웹 푸시를 못 쓰면: 페이지가 열려 있는 동안만
  if (Notification.permission === 'denied') return denied();
  if (Notification.permission === 'granted' && osOn()) return foot('다른 화면을 볼 때도 브라우저 알림을 보내요 · ',
    link('끄기', () => { try { localStorage.setItem('osNotify', 'off'); } catch {} paintNotes(); }));
  return foot(link('다른 화면을 볼 때도 브라우저로 알림 받기', async () => {
    try { localStorage.removeItem('osNotify'); } catch {}
    if (Notification.permission === 'default') await Notification.requestPermission().catch(() => {});
    paintNotes();
  }));
}

// 아이폰·아이패드: 홈 화면에 추가하는 방법
function installGuide() {
  document.querySelector('dialog.a2hs')?.remove();
  const close = () => dlg.close();
  const step = (...k) => el('li', {}, ...k);
  const share = el('span', { class: 'ico', 'aria-label': '공유 버튼' });
  share.innerHTML = SHARE_ICON; // 고정된 아이콘 문자열만
  const dlg = el('dialog', { class: 'a2hs', 'aria-labelledby': 'a2hsH' },
    el('div', { class: 'a2hs-head' }, el('h2', { id: 'a2hsH' }, '홈 화면에 추가하고 알림 받기'),
      el('button', { type: 'button', class: 'a2hs-x', 'aria-label': '닫기', onclick: close }, '×')),
    el('p', { class: 'a2hs-sub' }, '아이폰·아이패드는 Love Design 을 홈 화면에 추가해야 사이트를 닫아 둬도 알림을 받을 수 있어요.'),
    el('ol', {},
      step(el('b', {}, '공유 버튼'), share, '을 눌러요. ', el('span', { class: 'muted' }, '사파리는 화면 아래(아이패드는 위)에 있고, 안 보이면 주소창 옆 ', el('b', {}, '⋯'), ' 을 먼저 눌러요. 크롬은 주소창 오른쪽에 있어요.')),
      step('목록을 내려 ', el('b', {}, '홈 화면에 추가'), '를 누르고, ', el('b', {}, '추가'), '를 눌러요.'),
      step('홈 화면에 생긴 ', el('b', {}, 'Love Design'), ' 아이콘으로 열고 로그인해요. ', el('span', { class: 'muted' }, '홈 화면 앱은 브라우저와 로그인이 따로라서 한 번 더 로그인해야 해요.')),
      step('오른쪽 위 ', el('b', {}, '종 버튼'), '에서 ', el('b', {}, '이 기기로 알림 받기'), '를 누르고 ', el('b', {}, '허용'), '을 눌러요.')),
    notes.guest ? el('p', { class: 'a2hs-warn' }, '지금은 가입 없이 익명으로 이용 중이라 홈 화면 앱에서 다시 로그인할 수 없어요. 알림을 받으려면 ',
      el('a', { href: '/signup' }, '회원가입'), ' 후 이용해 주세요.') : null,
    el('button', { type: 'button', class: 'a2hs-ok', onclick: close }, '확인'));
  dlg.addEventListener('click', (e) => { if (e.target === dlg) close(); });
  dlg.addEventListener('close', () => dlg.remove());
  document.body.append(dlg);
  dlg.showModal();
}

// 이 화면을 지금 보고 있는지 서버에 알린다 → 보고 있지 않을 때만 기기로 푸시
function reportVisible(s) { s.emit('visible', document.visibilityState === 'visible'); }
function startNotes(user) {
  notes.guest = !!user.is_anonymous;
  if (notes.started) return;
  notes.started = true;
  loadNotes().then(syncPush);
  liveSocket().then((s) => {
    s.on('notify', (item) => { loadNotes(); if (item && !item.read) osNotify(item); });
    s.on('connect', () => { reportVisible(s); loadNotes(); }); // 끊겼다 다시 붙으면 그 사이 알림을 받아 온다
    if (s.connected) reportVisible(s);
    document.addEventListener('visibilitychange', () => reportVisible(s));
  }).catch(() => {});
  document.addEventListener('visibilitychange', () => { if (!document.hidden) loadNotes(); });
}
// 종 창을 연다 (다른 화면의 '알림 켜기' 안내에서)
function openNotes() {
  const box = document.querySelector('.noti');
  if (!box) return;
  scrollTo({ top: 0 });
  if (!box.classList.contains('open')) box.querySelector('.bell-btn').click();
}
function noteBell(user) {
  const btn = el('button', { type: 'button', class: 'bell-btn', 'aria-haspopup': 'true', 'aria-expanded': 'false' });
  btn.innerHTML = BELL_ICON; // 고정된 아이콘 문자열만
  btn.append(el('span', { class: 'badge', hidden: true }));
  const pop = el('div', { class: 'noti-pop', role: 'region', 'aria-label': '알림' });
  const box = el('div', { class: 'noti' }, btn, pop);
  const set = (open) => {
    box.classList.toggle('open', open); btn.setAttribute('aria-expanded', String(open));
    if (open) { pop.replaceChildren(...notePanel()); loadNotes(); }
  };
  btn.addEventListener('click', () => set(!box.classList.contains('open')));
  document.addEventListener('click', (e) => { if (box.isConnected && !box.contains(e.target) && !e.target.closest?.('dialog.a2hs')) set(false); });
  box.addEventListener('keydown', (e) => { if (e.key === 'Escape' && box.classList.contains('open')) { set(false); btn.focus(); } });
  startNotes(user);
  queueMicrotask(paintNotes);
  return box;
}

// 내 정보에서 닉네임·사진을 바꾸면 상단바도 바로 바꾼다
function refreshWho(u) { document.querySelectorAll('.me-menu').forEach((m) => m.replaceWith(meMenu(u))); }

// 모든 페이지(랜딩 포함)가 같은 상단바를 쓴다
function topbar(user) {
  const here = location.pathname.replace(/\.html$/, '');
  const link = (href, text) => el('a', { href, 'aria-current': here === href ? 'page' : false }, text);
  const nav = el('nav', { class: 'nav', 'aria-label': '주요 메뉴' });
  if (user) {
    nav.append(link('/my', '내 상담'));
    if (isStaffRole(user)) nav.append(link('/counselor', '상담사'), link('/records', '상담 기록'));
    if (user.role === 'admin') nav.append(link('/admin', '관리자'));
    nav.append(link('/guide', '이용방법'));
  } else {
    nav.append(link('/guide', '이용방법'), link('/about', '소개'), link('/login', '로그인'));
  }
  return el('header', { class: 'top' }, el('div', { class: 'top-in' },
    el('a', { class: 'logo', href: '/', 'aria-label': 'Love Design 처음으로' }, 'LD♡', el('small', {}, el('b', {}, 'L'), 'ove ', el('b', {}, 'D'), 'esign')),
    nav, themeButton(), user ? noteBell(user) : null, user ? meMenu(user) : null,
    user ? el('a', { class: 'cta', href: '/new' }, '새 상담') : el('a', { class: 'cta', href: '/signup' }, '회원가입')));
}

// 상단바를 그리고 로그인 정보를 돌려준다. need: true(로그인 필요) 또는 역할 배열
async function boot(need) {
  const me = await api('/api/me');
  const { user } = me;
  document.body.prepend(topbar(user));
  if (!document.querySelector('main.chat')) {
    document.body.append(el('footer', { class: 'foot' }, el('div', { class: 'foot-in' },
      el('nav', { 'aria-label': '사이트 안내' }, el('a', { href: '/guide' }, '이용방법안내'), el('a', { href: '/counsel' }, '고민 상담 안내'), el('a', { href: '/about' }, '사이트 소개'),
        el('a', { href: '/terms' }, '이용약관'), el('a', { href: '/privacy' }, el('b', {}, '개인정보처리방침')),
        el('a', { href: 'mailto:contact@yourloveour.design' }, '문의 contact@yourloveour.design')),
      el('span', { class: 'help' }, '위급할 땐 ', el('b', {}, '109'), ' 자살예방상담 · ', el('b', {}, '1388'), ' 청소년상담 · ', el('b', {}, '1577-0199'), ' 정신건강위기상담 · ', el('b', {}, '112·119')),
      themePicker(), el('span', {}, '© Love Design'))));
  }
  if (need && !user) { location.href = '/login?next=' + encodeURIComponent(location.pathname + location.search); throw new Error('login'); }
  if (Array.isArray(need) && !need.includes(user.role)) { document.querySelector('main').replaceChildren(el('p', {}, '권한이 없어요.')); throw new Error('role'); }
  return me; // { user, categories, social }
}

// ── X 로그인 ──
const X_ICON = '<svg viewBox="0 0 24 24" width="16" height="16" fill="currentColor" aria-hidden="true"><path d="M18.244 2.25h3.308l-7.227 8.26 8.502 11.24H16.17l-5.214-6.817L4.99 21.75H1.68l7.73-8.835L1.254 2.25H8.08l4.713 6.231zm-1.161 17.52h1.833L7.084 4.126H5.117z"/></svg>';
const XERR = {
  off: 'X 로그인이 아직 준비되지 않았어요.',
  denied: 'X 로그인을 취소했어요.',
  expired: '시간이 지났거나 잘못된 요청이에요. 다시 시도해주세요.',
  fail: 'X와 연결하지 못했어요. 잠시 후 다시 시도해주세요.',
  banned: '이용이 정지된 계정이에요.',
  taken: '이 X 계정은 이미 다른 회원에게 연결돼 있어요. 그 계정으로 X 로그인해주세요.',
  already: '이미 다른 X 계정이 연결돼 있어요. 연결을 해제한 뒤 다시 시도해주세요.',
};
// X 에서 돌아온 결과(?xerr= / ?x=)를 읽고 주소창에서 지운다
function xResult() {
  const sp = new URLSearchParams(location.search);
  const r = { error: sp.has('xerr') ? (XERR[sp.get('xerr')] || XERR.fail) : '', ok: sp.get('x') };
  if (sp.has('xerr') || sp.has('x')) {
    sp.delete('xerr'); sp.delete('x');
    history.replaceState(null, '', location.pathname + (String(sp) ? '?' + sp : '') + location.hash);
  }
  return r;
}
// X 로 시작하는 링크 버튼 (서버가 X 동의 화면으로 넘긴다)
function xButton(text, href) {
  const a = el('a', { class: 'btn wide btn-x', href });
  a.insertAdjacentHTML('afterbegin', X_ICON); // 고정된 아이콘 문자열만 넣는다
  a.append(text);
  return a;
}

function fmt(d) { return d ? d.slice(0, 16).replace('T', ' ') : ''; }
