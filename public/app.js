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
const ROLE = { user: '일반', counselor: '상담자', admin: '관리자' };
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
async function logout(e) { e?.preventDefault(); await api('/api/logout', {}); location.href = '/'; }

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
// 내 정보에서 닉네임·사진을 바꾸면 상단바도 바로 바꾼다
function refreshWho(u) { document.querySelectorAll('.me-menu').forEach((m) => m.replaceWith(meMenu(u))); }

// 모든 페이지(랜딩 포함)가 같은 상단바를 쓴다
function topbar(user) {
  const here = location.pathname.replace(/\.html$/, '');
  const link = (href, text) => el('a', { href, 'aria-current': here === href ? 'page' : false }, text);
  const nav = el('nav', { class: 'nav', 'aria-label': '주요 메뉴' });
  if (user) {
    nav.append(link('/my', '내 상담'));
    if (isStaffRole(user)) nav.append(link('/counselor', '상담자'), link('/records', '상담 기록'));
    if (user.role === 'admin') nav.append(link('/admin', '관리자'));
    nav.append(link('/guide', '이용방법'));
  } else {
    nav.append(link('/guide', '이용방법'), link('/about', '소개'), link('/login', '로그인'));
  }
  return el('header', { class: 'top' }, el('div', { class: 'top-in' },
    el('a', { class: 'logo', href: '/', 'aria-label': 'Love Design 처음으로' }, 'LD♡', el('small', {}, el('b', {}, 'L'), 'ove ', el('b', {}, 'D'), 'esign')),
    nav, user ? meMenu(user) : null,
    user ? el('a', { class: 'cta', href: '/new' }, '새 상담') : el('a', { class: 'cta', href: '/signup' }, '회원가입')));
}

// 상단바를 그리고 로그인 정보를 돌려준다. need: true(로그인 필요) 또는 역할 배열
async function boot(need) {
  const { user, categories } = await api('/api/me');
  document.body.prepend(topbar(user));
  if (!document.querySelector('main.chat')) {
    document.body.append(el('footer', { class: 'foot' }, el('div', { class: 'foot-in' },
      el('nav', { 'aria-label': '사이트 안내' }, el('a', { href: '/guide' }, '이용방법안내'), el('a', { href: '/about' }, '사이트 소개')),
      el('span', { class: 'help' }, '위급할 땐 ', el('b', {}, '109'), ' 자살예방상담 · ', el('b', {}, '1577-0199'), ' 정신건강위기상담 · ', el('b', {}, '112·119')),
      el('span', {}, '© Love Design'))));
  }
  if (need && !user) { location.href = '/login?next=' + encodeURIComponent(location.pathname + location.search); throw new Error('login'); }
  if (Array.isArray(need) && !need.includes(user.role)) { document.querySelector('main').replaceChildren(el('p', {}, '권한이 없어요.')); throw new Error('role'); }
  return { user, categories };
}

function fmt(d) { return d ? d.slice(0, 16).replace('T', ' ') : ''; }
