const fs = require('node:fs');
const path = require('node:path');
const mysql = require('mysql2/promise');
const bcrypt = require('bcryptjs');

const url = process.env.DATABASE_URL || 'mysql://root@127.0.0.1:3306/love_design';
const pool = mysql.createPool({ uri: url, charset: 'utf8mb4', dateStrings: true, connectionLimit: 10 });

async function init() {
  const sql = fs.readFileSync(path.join(__dirname, 'schema.sql'), 'utf8');
  for (const stmt of sql.split(';').map(s => s.trim()).filter(Boolean)) await pool.query(stmt);
  // 기존 DB 마이그레이션: CREATE TABLE IF NOT EXISTS 는 컬럼을 추가해주지 않는다
  const [[col]] = await pool.query(
    "SELECT COUNT(*) AS n FROM information_schema.columns WHERE table_schema = DATABASE() AND table_name = 'users' AND column_name = 'session_ver'");
  if (!col.n) await pool.query('ALTER TABLE users ADD COLUMN session_ver INT NOT NULL DEFAULT 0');

  const { ADMIN_EMAIL, ADMIN_PASSWORD } = process.env;
  if (ADMIN_EMAIL && ADMIN_PASSWORD) {
    const [rows] = await pool.query('SELECT id FROM users WHERE email = ?', [ADMIN_EMAIL]);
    if (rows.length) {
      await pool.query("UPDATE users SET role = 'admin' WHERE id = ?", [rows[0].id]);
    } else {
      await pool.query(
        "INSERT INTO users (email, password_hash, nickname, role) VALUES (?, ?, '관리자', 'admin')",
        [ADMIN_EMAIL, await bcrypt.hash(ADMIN_PASSWORD, 10)]
      );
    }
  }
}

module.exports = { pool, init, url };
