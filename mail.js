const nodemailer = require('nodemailer');

const { SMTP_HOST, SMTP_PORT, SMTP_USER, SMTP_PASS, SMTP_SECURE, SMTP_FROM } = process.env;
const port = Number(SMTP_PORT || 587);
// 사이트의 모든 문의는 이 주소로 받는다 (관리자 페이지 > 메일함)
const CONTACT = 'contact@yourloveour.design';

const transport = SMTP_HOST && nodemailer.createTransport({
  host: SMTP_HOST,
  port,
  secure: SMTP_SECURE ? SMTP_SECURE === 'true' : port === 465, // 465 = SSL, 587 = STARTTLS
  auth: SMTP_USER ? { user: SMTP_USER, pass: SMTP_PASS } : undefined,
});

const mail = {
  contact: CONTACT,
  // SMTP 미설정 시: 개발 환경에선 콘솔에 출력, 운영(NODE_ENV=production)에선 발송 불가
  enabled: !!transport || process.env.NODE_ENV !== 'production',
  async send({ to, subject, text, html }) {
    if (!transport) {
      if (process.env.NODE_ENV === 'production') throw new Error('SMTP 미설정');
      console.log(`[mail:dev] to=${to} subject=${subject}\n${text}`);
      return;
    }
    await transport.sendMail({ from: SMTP_FROM || SMTP_USER, replyTo: CONTACT, to, subject, text, html });
  },
};

// ── 메일 템플릿 ──
// 메일 클라이언트는 <style>·flex·외부 폰트를 잘 지원하지 않는다 → 표 레이아웃 + 인라인 스타일
const C = { ink: '#161616', muted: '#7a7470', soft: '#b9b2ad', rose: '#e14b62', roseSoft: '#f6d6db', line: '#eee9e6', tint: '#faf7f5' };
const FONT = "-apple-system,BlinkMacSystemFont,'Apple SD Gothic Neo','Malgun Gothic','맑은 고딕',sans-serif";

function layout({ preheader, body }) {
  return `<!doctype html>
<html lang="ko">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="color-scheme" content="light">
<meta name="supported-color-schemes" content="light">
<title>Love Design</title>
</head>
<body style="margin:0;padding:0;background:${C.tint};-webkit-text-size-adjust:100%;word-break:keep-all">
<div style="display:none;max-height:0;overflow:hidden;opacity:0;color:transparent">${preheader}</div>
<table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0" style="background:${C.tint}">
<tr><td align="center" style="padding:40px 16px">
  <table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0" style="max-width:480px;font-family:${FONT};color:${C.ink}">
    <tr><td style="padding:0 8px 20px">
      <span style="font-size:22px;font-weight:800;letter-spacing:-0.5px;color:${C.ink}">LD<span style="color:${C.rose}">&#9825;</span></span>
      <span style="font-size:13px;color:${C.muted};padding-left:6px"><b style="color:${C.rose}">L</b>ove <b style="color:${C.rose}">D</b>esign</span>
    </td></tr>
    <tr><td style="background:#ffffff;border:1px solid ${C.line};border-radius:20px;padding:40px 32px">
      ${body}
    </td></tr>
    <tr><td style="padding:24px 8px 0;font-size:12px;line-height:1.7;color:${C.soft}">
      궁금한 점은 <a href="mailto:${CONTACT}" style="color:${C.muted};text-decoration:underline">${CONTACT}</a> 로 문의해주세요.<br>
      위급할 땐 <span style="white-space:nowrap"><b style="color:${C.muted}">109</b> 자살예방상담</span> · <span style="white-space:nowrap"><b style="color:${C.muted}">1577-0199</b> 정신건강위기상담</span> · <b style="color:${C.muted}">112·119</b><br>
      &copy; Love Design
    </td></tr>
  </table>
</td></tr>
</table>
</body>
</html>`;
}

// 인증번호 메일 — 회원가입(signup) / 비밀번호 찾기(reset) / 비밀번호 변경(password)
const CODE_TEXT = {
  signup: {
    title: 'Love Design 회원가입 인증번호', h1: '이메일 인증번호예요', where: '회원가입 화면의 인증번호 칸에',
    ignore: '계정은 만들어지지 않아요.', ignoreLong: '인증번호를 입력하지 않으면 계정은 만들어지지 않아요.',
  },
  reset: {
    title: 'Love Design 비밀번호 찾기 인증번호', h1: '비밀번호 찾기 인증번호예요', where: '비밀번호 찾기 화면의 인증번호 칸에',
    ignore: '비밀번호는 바뀌지 않아요.', ignoreLong: '인증번호를 입력하지 않으면 비밀번호는 바뀌지 않아요.',
  },
  password: {
    title: 'Love Design 비밀번호 변경 인증번호', h1: '비밀번호 변경 인증번호예요', where: '내 정보 > 비밀번호 변경 창의 인증번호 칸에',
    ignore: '비밀번호는 바뀌지 않아요.', ignoreLong: '인증번호를 입력하지 않으면 비밀번호는 바뀌지 않아요.',
  },
};
mail.verifyCode = (code, kind = 'signup') => {
  const t = CODE_TEXT[kind];
  return {
    subject: kind === 'signup' ? `[Love Design] 인증번호 ${code}` : `[Love Design] ${t.h1.replace(' 인증번호예요', '')} 인증번호 ${code}`,
    text: `${t.title}는 ${code} 입니다.\n10분 안에 입력해주세요.\n\n본인이 요청하지 않았다면 이 메일을 무시하세요. ${t.ignore}\n\n문의: ${CONTACT}`,
    html: layout({
      preheader: `인증번호 ${code} · 10분 안에 입력해주세요.`,
      body: `
      <p style="margin:0 0 10px;font-size:12px;font-weight:700;letter-spacing:3px;color:${C.rose}">EMAIL VERIFICATION</p>
      <h1 style="margin:0 0 12px;font-size:24px;line-height:1.35;letter-spacing:-0.5px;font-weight:800;color:${C.ink}">${t.h1}</h1>
      <p style="margin:0 0 28px;font-size:15px;line-height:1.7;color:${C.muted}">${t.where} 아래 숫자 6자리를 입력해주세요.</p>
      <table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0">
        <tr><td align="center" style="background:${C.tint};border:1px solid ${C.roseSoft};border-radius:16px;padding:26px 12px">
          <span style="font-family:'SF Mono',Menlo,Consolas,'Courier New',monospace;font-size:38px;line-height:1;font-weight:700;letter-spacing:10px;color:${C.ink};padding-left:10px">${code}</span>
        </td></tr>
      </table>
      <p style="margin:16px 0 0;font-size:13px;color:${C.muted};text-align:center">
        <span style="display:inline-block;background:${C.roseSoft};color:${C.rose};font-weight:700;border-radius:999px;padding:3px 12px">10분 동안 유효</span>
      </p>
      <hr style="border:0;border-top:1px solid ${C.line};margin:32px 0 20px">
      <p style="margin:0;font-size:13px;line-height:1.7;color:${C.muted}">
        본인이 요청하지 않았다면 이 메일을 무시해주세요. ${t.ignoreLong}
        인증번호는 누구에게도 알려주지 마세요.
      </p>`,
    }),
  };
};

// 이미 가입된 이메일로 가입 인증번호를 요청했을 때 (가입 여부를 화면에 알리지 않는 대신 메일함 주인에게만 알린다)
const SITE = 'https://yourloveour.design';
mail.alreadyJoined = () => ({
  subject: '[Love Design] 이미 가입된 이메일이에요',
  text: `이 이메일로 가입한 Love Design 계정이 이미 있어서 인증번호를 보내지 않았어요.\n\n로그인: ${SITE}/login\n비밀번호가 기억나지 않으면: ${SITE}/reset\n\n본인이 요청하지 않았다면 이 메일을 무시하세요. 계정에는 아무 변화가 없어요.\n\n문의: ${CONTACT}`,
  html: layout({
    preheader: '이 이메일로 가입한 계정이 이미 있어요.',
    body: `
      <p style="margin:0 0 10px;font-size:12px;font-weight:700;letter-spacing:3px;color:${C.rose}">ALREADY A MEMBER</p>
      <h1 style="margin:0 0 12px;font-size:24px;line-height:1.35;letter-spacing:-0.5px;font-weight:800;color:${C.ink}">이미 가입된 이메일이에요</h1>
      <p style="margin:0 0 28px;font-size:15px;line-height:1.7;color:${C.muted}">이 이메일로 가입한 계정이 이미 있어서 인증번호를 보내지 않았어요. 새로 가입하지 않고 그대로 로그인하면 돼요.</p>
      <table role="presentation" cellpadding="0" cellspacing="0" border="0"><tr>
        <td style="background:${C.rose};border-radius:999px"><a href="${SITE}/login" style="display:inline-block;padding:13px 26px;font-size:15px;font-weight:700;color:#ffffff;text-decoration:none">로그인하기</a></td>
      </tr></table>
      <p style="margin:16px 0 0;font-size:14px;line-height:1.7;color:${C.muted}">비밀번호가 기억나지 않으면 <a href="${SITE}/reset" style="color:${C.rose};font-weight:700">비밀번호 찾기</a>에서 새로 정할 수 있어요.</p>
      <hr style="border:0;border-top:1px solid ${C.line};margin:32px 0 20px">
      <p style="margin:0;font-size:13px;line-height:1.7;color:${C.muted}">본인이 요청하지 않았다면 이 메일을 무시해주세요. 계정에는 아무 변화가 없어요.</p>`,
  }),
});

module.exports = mail;
