// X(트위터) 로그인 — OAuth 2.0 Authorization Code + PKCE
// https://docs.x.com/resources/fundamentals/authentication/oauth-2-0/authorization-code
// 토큰은 프로필(id·아이디·이름)을 한 번 읽는 데만 쓰고 바로 폐기한다 (저장하지 않음).
const crypto = require('node:crypto');

const CLIENT_ID = process.env.X_CLIENT_ID || '';
const CLIENT_SECRET = process.env.X_CLIENT_SECRET || ''; // 없으면 public client 로 동작
const SCOPE = 'users.read tweet.read'; // users/me 는 두 scope 가 모두 있어야 읽힌다
const AUTHORIZE = 'https://x.com/i/oauth2/authorize';
const API = 'https://api.x.com/2';

const b64url = (buf) => Buffer.from(buf).toString('base64url');

const x = {
  get enabled() { return !!CLIENT_ID; },
  http: (...a) => fetch(...a), // 테스트에서 바꿔 끼운다

  // state·code_verifier 를 만들어 돌려준다 (세션에 보관)
  start(redirectUri) {
    const state = b64url(crypto.randomBytes(24));
    const verifier = b64url(crypto.randomBytes(48));
    const challenge = b64url(crypto.createHash('sha256').update(verifier).digest());
    const url = AUTHORIZE + '?' + new URLSearchParams({
      response_type: 'code', client_id: CLIENT_ID, redirect_uri: redirectUri, scope: SCOPE,
      state, code_challenge: challenge, code_challenge_method: 'S256',
    });
    return { url, state, verifier };
  },

  // 인가 코드 → 액세스 토큰 → 프로필 { id, username, name }
  async profile(code, verifier, redirectUri) {
    const headers = { 'Content-Type': 'application/x-www-form-urlencoded' };
    if (CLIENT_SECRET) headers.Authorization = 'Basic ' + Buffer.from(`${CLIENT_ID}:${CLIENT_SECRET}`).toString('base64');
    const form = { code, grant_type: 'authorization_code', redirect_uri: redirectUri, code_verifier: verifier, client_id: CLIENT_ID };
    const tr = await x.http(API + '/oauth2/token', { method: 'POST', headers, body: new URLSearchParams(form), signal: AbortSignal.timeout(10000) });
    const tok = await tr.json().catch(() => ({}));
    if (!tr.ok || !tok.access_token) throw new Error(`X token ${tr.status} ${tok.error || ''}`);
    try {
      const ur = await x.http(API + '/users/me', { headers: { Authorization: 'Bearer ' + tok.access_token }, signal: AbortSignal.timeout(10000) });
      const me = (await ur.json().catch(() => ({}))).data;
      if (!ur.ok || !me?.id) throw new Error(`X users/me ${ur.status}`);
      return { id: String(me.id), username: String(me.username || ''), name: String(me.name || '') };
    } finally {
      // 더 쓸 일이 없으니 바로 폐기 (실패해도 2시간 뒤 만료)
      x.http(API + '/oauth2/revoke', {
        method: 'POST', headers, body: new URLSearchParams({ token: tok.access_token, token_type_hint: 'access_token', client_id: CLIENT_ID }),
        signal: AbortSignal.timeout(5000),
      }).catch(() => {});
    }
  },
};

module.exports = x;
