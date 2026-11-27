const nodemailer = require('nodemailer');

const { SMTP_HOST, SMTP_PORT, SMTP_USER, SMTP_PASS, SMTP_SECURE, SMTP_FROM } = process.env;
const port = Number(SMTP_PORT || 587);

const transport = SMTP_HOST && nodemailer.createTransport({
  host: SMTP_HOST,
  port,
  secure: SMTP_SECURE ? SMTP_SECURE === 'true' : port === 465, // 465 = SSL, 587 = STARTTLS
  auth: SMTP_USER ? { user: SMTP_USER, pass: SMTP_PASS } : undefined,
});

const mail = {
  // SMTP 미설정 시: 개발 환경에선 콘솔에 출력, 운영(NODE_ENV=production)에선 발송 불가
  enabled: !!transport || process.env.NODE_ENV !== 'production',
  async send({ to, subject, text, html }) {
    if (!transport) {
      if (process.env.NODE_ENV === 'production') throw new Error('SMTP 미설정');
      console.log(`[mail:dev] to=${to} subject=${subject}\n${text}`);
      return;
    }
    await transport.sendMail({ from: SMTP_FROM || SMTP_USER, to, subject, text, html });
  },
};

module.exports = mail;
