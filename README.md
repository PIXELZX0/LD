# LD — Love Design 고민상담

Node + Express + socket.io + MySQL. 익명/회원 상담, 상담자 지원·승인, 관리자 페이지, 1:1 실시간 채팅.

- `server.js` — API, 인증, 실시간 채팅
- `mail.js` — SMTP 메일 발송 (회원가입 이메일 인증)
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

`SMTP_HOST` 가 없으면 개발 환경에선 인증번호를 콘솔에 출력하고, 운영(`NODE_ENV=production`)에선 회원가입이 막혀요.

## 배포
Coolify: MySQL 리소스 생성 → 앱(`ld-web`)에 위 env 설정, 포트 3000.
`main` push → CI(테스트·이미지 확인) 통과 시 Coolify 배포.
