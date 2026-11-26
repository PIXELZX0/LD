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
  const nav = el('nav', { class: 'nav' });
  if (user) {
    if (user.role === 'counselor' || user.role === 'admin') nav.append(el('a', { href: '/counselor' }, '상담자'));
    if (user.role === 'admin') nav.append(el('a', { href: '/admin' }, '관리자'));
    nav.append(el('a', { href: '/new' }, '새 상담'), el('a', { href: '/my' }, user.nickname),
      el('a', { href: '#', onclick: async (e) => { e.preventDefault(); await api('/api/logout', {}); location.href = '/'; } }, '로그아웃'));
  } else {
    nav.append(el('a', { href: '/guide' }, '이용방법'), el('a', { href: '/about' }, '소개'), el('a', { href: '/login' }, '로그인'));
  }
  document.body.prepend(el('header', { class: 'top' },
    el('a', { class: 'logo', href: '/' }, 'LD♡', el('small', {}, el('b', {}, 'L'), 'ove ', el('b', {}, 'D'), 'esign')), nav));
  if (need && !user) { location.href = '/login?next=' + encodeURIComponent(location.pathname + location.search); throw new Error('login'); }
  if (Array.isArray(need) && !need.includes(user.role)) { document.querySelector('main').replaceChildren(el('p', {}, '권한이 없어요.')); throw new Error('role'); }
  return { user, categories };
}

function fmt(d) { return d ? d.slice(0, 16).replace('T', ' ') : ''; }
