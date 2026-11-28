// 서비스 워커: 웹 푸시만 받는다 (오프라인 캐시는 하지 않음 — 상담 내용을 기기에 남기지 않는다)
self.addEventListener('install', () => self.skipWaiting());
self.addEventListener('activate', (e) => e.waitUntil(self.clients.claim()));

self.addEventListener('push', (e) => {
  let d = {};
  try { d = e.data ? e.data.json() : {}; } catch {}
  // 푸시를 받으면 반드시 알림을 띄운다 (안 띄우면 브라우저가 푸시 권한을 거둘 수 있다)
  e.waitUntil(self.registration.showNotification(d.title || 'Love Design', {
    body: d.body || '새 알림이 있어요.',
    tag: d.tag, renotify: !!d.tag,
    icon: '/icon-192.png',
    data: { link: d.link },
  }));
});

// 알림을 누르면 그 화면으로: 이미 열린 창이 있으면 그 창에서, 없으면 새로 연다
self.addEventListener('notificationclick', (e) => {
  e.notification.close();
  let url = new URL('/my', self.location.origin);
  try {
    const u = new URL(e.notification.data?.link || '/my', self.location.origin);
    if (u.origin === self.location.origin) url = u;
  } catch {}
  e.waitUntil((async () => {
    const wins = await self.clients.matchAll({ type: 'window', includeUncontrolled: true });
    const same = wins.find((w) => w.url === url.href);
    if (same) return same.focus();
    const any = wins.find((w) => 'navigate' in w);
    if (any) {
      try { const w = await any.navigate(url.href); return (w || any).focus(); } catch {}
    }
    return self.clients.openWindow(url.href);
  })());
});
