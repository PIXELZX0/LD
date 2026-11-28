// 웹 푸시 (사이트를 닫아 둬도 오는 알림). VAPID 키가 없으면 꺼진다 — 종 알림은 그대로 동작
// 키 만들기: npx web-push generate-vapid-keys → VAPID_PUBLIC_KEY / VAPID_PRIVATE_KEY
// 키를 바꾸면 기존 구독이 모두 끊긴다 (회원이 알림을 다시 켜야 함)
const webpush = require('web-push');

const { VAPID_PUBLIC_KEY: publicKey, VAPID_PRIVATE_KEY: privateKey } = process.env;
let enabled = false;
if (publicKey && privateKey) {
  try {
    webpush.setVapidDetails(process.env.VAPID_SUBJECT || 'mailto:contact@yourloveour.design', publicKey, privateKey);
    enabled = true;
  } catch (e) {
    console.error('웹 푸시 꺼짐: VAPID 키를 확인해주세요.', e.message);
  }
}

// 우리 서버가 대신 요청을 보내는 주소라서 (SSRF) 알려진 푸시 서비스로만 보낸다
const PUSH_HOSTS = /^(fcm\.googleapis\.com|android\.googleapis\.com|([a-z0-9-]+\.)*push\.apple\.com|([a-z0-9-]+\.)*push\.services\.mozilla\.com|([a-z0-9-]+\.)*notify\.windows\.com)$/;
function okEndpoint(v) {
  if (typeof v !== 'string' || v.length > 1000) return false;
  try {
    const u = new URL(v);
    return u.protocol === 'https:' && !u.port && !u.username && !u.password && PUSH_HOSTS.test(u.hostname);
  } catch { return false; }
}
// 브라우저가 준 암호화 키: p256dh 는 P-256 공개키(65바이트), auth 는 16바이트
const b64len = (v, n) => typeof v === 'string' && /^[A-Za-z0-9_-]+={0,2}$/.test(v) && Buffer.from(v, 'base64url').length === n;
const okKeys = (k) => !!k && b64len(k.p256dh, 65) && b64len(k.auth, 16);

module.exports = {
  get enabled() { return enabled; },
  publicKey: enabled ? publicKey : null,
  okEndpoint, okKeys,
  // 실패하면 statusCode 가 붙은 오류 (404·410 = 구독이 사라짐)
  send: (sub, payload) => webpush.sendNotification(sub, JSON.stringify(payload), { TTL: 24 * 60 * 60, urgency: 'high' }),
};
