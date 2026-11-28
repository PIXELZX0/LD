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
    if (isStaffRole(user)) nav.append(link('/counselor', '상담사'), link('/records', '상담 기록'));
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
