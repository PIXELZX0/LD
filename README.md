# LD — Love Design 고민상담

Node + Express + socket.io + MySQL. 익명/회원 상담, 상담자 지원·승인, 관리자 페이지, 1:1 실시간 채팅.

- `server.js` — API, 인증, 실시간 채팅
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

## 배포
Coolify: MySQL 리소스 생성 → 앱(`ld-web`)에 위 env 설정, 포트 3000.
`main` push → CI(테스트·이미지 확인) 통과 시 Coolify 배포.
