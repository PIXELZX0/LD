# LD — Love Design 고민상담

Node + Express + socket.io + MySQL. 익명/회원 상담, 상담사 지원·승인, 관리자 페이지, 1:1 실시간 채팅, 패스키 로그인, 상담 기록(상담사 메모·내담자 후기), 알림.

- `server.js` — API, 인증, 실시간 채팅
- `xauth.js` — X(트위터) 로그인 (OAuth 2.0 + PKCE)
- `push.js` — 웹 푸시 발송 (VAPID), `public/sw.js` 서비스 워커가 받아서 띄운다
- `mail.js` — SMTP 메일 발송 (회원가입 이메일 인증)
- `inbox.js` — 문의 메일함 (관리자 페이지 > 메일함, IMAP 읽기·SMTP 답장, HTML 메일은 격리된 iframe 으로 표시, 받은편지함을 주기적으로 확인해 새 메일 원문을 `mail_cache` 테이블에 저장, 받은 지 30일 지난 읽은 메일 저장본은 자동 삭제 — 메일 서버의 메일은 지우지 않음)
- `db.js` / `schema.sql` — MySQL 연결, 부팅 시 테이블 자동 생성 + 관리자 시드
- `public/` — 페이지 (빌드 없음)
- `test.js` — 스모크 테스트 (`DATABASE_URL=... npm test`)

## 환경변수
| 이름 | 설명 |
|---|---|
| `DATABASE_URL` | `mysql://user:pass@host:3306/love_design` |
| `SESSION_SECRET` | 긴 랜덤 문자열 (필수) |
| `ADMIN_EMAIL` / `ADMIN_PASSWORD` | 부팅 시 이 계정을 관리자로 생성/승격 |
| `PORT` | 기본 3000 |
| `SMTP_HOST` | 회원가입 인증메일 SMTP 서버 (예: `smtp.gmail.com`) |
| `SMTP_PORT` | 기본 587 (STARTTLS). 465면 SSL 자동 |
| `SMTP_SECURE` | `true`/`false` 로 SSL 강제 지정 (선택) |
| `SMTP_USER` / `SMTP_PASS` | SMTP 계정 (Gmail은 앱 비밀번호) |
| `SMTP_FROM` | 보내는 사람, 예: `Love Design <no-reply@example.com>` (기본 `SMTP_USER`) |
| `CONTACT_MAIL_USER` / `CONTACT_MAIL_PASS` | 문의 메일함 계정, 예: `contact@yourloveour.design` (없으면 메일함 꺼짐) |
| `CONTACT_IMAP_HOST` / `CONTACT_IMAP_PORT` | IMAP 서버 (기본 `SMTP_HOST` / 993) |
| `CONTACT_SMTP_HOST` / `CONTACT_SMTP_PORT` | 답장 보낼 SMTP (기본 `SMTP_HOST` / `SMTP_PORT`) |
| `CONTACT_MAIL_FROM` | 답장 보내는 사람 (기본 `Love Design <CONTACT_MAIL_USER>`) |
| `CONTACT_POLL_SEC` | 받은편지함 확인 주기 (초, 기본 60, 최소 15) |
| `WEBAUTHN_RP_ID` | 패스키 RP ID, 예: `example.com` (선택, 기본은 요청 호스트) |
| `WEBAUTHN_ORIGIN` | 패스키 origin, 예: `https://example.com` (선택, 기본은 요청 프로토콜+호스트) |
| `X_CLIENT_ID` / `X_CLIENT_SECRET` | X 로그인 OAuth 2.0 Client ID / Secret (없으면 X 버튼이 안 보임) |
| `VAPID_PUBLIC_KEY` / `VAPID_PRIVATE_KEY` | 웹 푸시 키 (`npx web-push generate-vapid-keys` 로 만든다, 없으면 기기 알림이 꺼지고 종 알림만). 바꾸면 기존 구독이 모두 끊김 |
| `VAPID_SUBJECT` | 푸시 서비스에 알릴 연락처 (기본 `mailto:contact@yourloveour.design`) |
| `X_REDIRECT_URI` | X 콜백 주소 (선택, 기본 `요청 프로토콜+호스트/api/auth/x/callback`) |

`SMTP_HOST` 가 없으면 개발 환경에선 인증번호를 콘솔에 출력하고, 운영(`NODE_ENV=production`)에선 회원가입이 막혀요.

패스키: 회원이 `내 정보`(/account)에서 등록하고, 로그인 화면에서 이메일 없이 로그인해요 (`@simplewebauthn`).
X 로그인: [X 개발자 포털](https://developer.x.com)에서 앱의 User authentication settings 를 켜고
(App permissions `Read`, Type of App `Web App` = confidential client), Callback URI 에 `https://yourloveour.design/api/auth/x/callback` 을 넣은 뒤
OAuth 2.0 Client ID·Secret 을 env 에 넣어요. 처음 보는 X 계정은 약관 동의·닉네임을 받아 새로 가입시키고(이메일·비밀번호 없음),
회원은 `내 정보`에서 X 를 연결·해제하고, X 로만 가입한 회원은 이메일 인증 + 비밀번호로 이메일 로그인을 추가할 수 있어요. 로그인 방법(이메일+비밀번호 / X / 패스키)이 하나도 남지 않게 되는 해제·삭제는 막아요.
X 토큰은 프로필을 한 번 읽고 바로 폐기해요 (저장 안 함).

알림: 상단바 종 버튼. 새 상담 요청(상담사·관리자), 상담사 배정·상담 종료(상대방), 새 메시지(상대방이 그 상담 화면을 열어 두지 않았을 때, 읽기 전까지 한 줄로 묶음),
상담사 지원(관리자)·지원 결과(지원자)를 `notifications` 테이블에 남기고 열린 화면엔 소켓(`u:회원번호` 방)으로 바로 보내요. 상담을 열면 그 상담 알림은 읽음.
종 창의 '이 기기로 알림 받기'를 누르면 웹 푸시로 사이트를 닫아 둬도 기기에 알림이 와요 (그 회원이 사이트를 보고 있을 땐 종 알림만).
잠금화면에 보일 수 있어 기기 알림엔 상담 제목·이름을 넣지 않아요. 아이폰·아이패드는 홈 화면에 추가한 앱에서만 웹 푸시가 돼서(iOS 16.4+)
브라우저로 열면 '홈 화면에 추가하고 알림 받기' 안내를 보여 줘요 (`manifest.webmanifest`). 로그아웃하면 그 기기 구독을 지우고,
비밀번호 변경·다른 기기 로그아웃 뒤엔 그 전에 등록한 기기로 보내지 않아요. 푸시는 알려진 푸시 서비스(FCM·Apple·Mozilla·Windows) 주소로만 보내요.
읽은 지 30일·받은 지 90일 지난 알림은 서버가 지워요.

도메인을 바꾸면 기존 패스키는 쓸 수 없어요 (RP ID 가 도메인에 묶임). 운영은 HTTPS 필수.

## 배포
Coolify: MySQL 리소스 생성 → 앱(`ld-web`)에 위 env 설정, 포트 3000.
`main` push → CI(테스트·이미지 확인) 통과 시 Coolify 배포.
