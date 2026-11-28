# LD — Love Design 고민상담

Node + Express + socket.io + MySQL. 익명/회원 상담, 상담자 지원·승인, 관리자 페이지, 1:1 실시간 채팅, 패스키 로그인, 상담 기록(상담자 메모·내담자 후기).

- `server.js` — API, 인증, 실시간 채팅
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

`SMTP_HOST` 가 없으면 개발 환경에선 인증번호를 콘솔에 출력하고, 운영(`NODE_ENV=production`)에선 회원가입이 막혀요.

패스키: 회원이 `내 정보`(/account)에서 등록하고, 로그인 화면에서 이메일 없이 로그인해요 (`@simplewebauthn`).
도메인을 바꾸면 기존 패스키는 쓸 수 없어요 (RP ID 가 도메인에 묶임). 운영은 HTTPS 필수.

## 배포
Coolify: MySQL 리소스 생성 → 앱(`ld-web`)에 위 env 설정, 포트 3000.
`main` push → CI(테스트·이미지 확인) 통과 시 Coolify 배포.
