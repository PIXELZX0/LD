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

// 상단바를 그리고 로그인 정보를 돌려준다. need: true(로그인 필요) 또는 역할 배열
async function boot(need) {
  const { user, categories } = await api('/api/me');
  const here = location.pathname.replace(/\.html$/, '');
  const link = (href, text) => el('a', { href, 'aria-current': here === href ? 'page' : false }, text);
  const nav = el('nav', { class: 'nav', 'aria-label': '주요 메뉴' });
  if (user) {
    nav.append(el('span', { class: 'who-chip' }, user.nickname + (user.is_anonymous ? ' (익명)' : '') + '님'), link('/my', '내 상담'), link('/account', '내 정보'));
    if (user.role === 'counselor' || user.role === 'admin') nav.append(link('/counselor', '상담자'));
    if (user.role === 'admin') nav.append(link('/admin', '관리자'));
    nav.append(el('a', { href: '#', onclick: async (e) => { e.preventDefault(); await api('/api/logout', {}); location.href = '/'; } }, '로그아웃'));
  } else {
    nav.append(link('/guide', '이용방법'), link('/about', '소개'), link('/login', '로그인'));
  }
  document.body.prepend(el('header', { class: 'top' }, el('div', { class: 'top-in' },
    el('a', { class: 'logo', href: '/', 'aria-label': 'Love Design 처음으로' }, 'LD♡', el('small', {}, el('b', {}, 'L'), 'ove ', el('b', {}, 'D'), 'esign')),
    nav, user ? el('a', { class: 'btn sm primary cta', href: '/new' }, '새 상담') : el('a', { class: 'btn sm primary cta', href: '/signup' }, '회원가입'))));
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
