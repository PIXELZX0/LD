CREATE TABLE IF NOT EXISTS users (
  id INT AUTO_INCREMENT PRIMARY KEY,
  email VARCHAR(190) NULL UNIQUE,
  password_hash VARCHAR(100) NULL,
  nickname VARCHAR(40) NOT NULL,
  role ENUM('user','counselor','admin') NOT NULL DEFAULT 'user',
  is_anonymous TINYINT(1) NOT NULL DEFAULT 0,
  banned TINYINT(1) NOT NULL DEFAULT 0,
  session_ver INT NOT NULL DEFAULT 0,
  avatar CHAR(16) NULL,
  terms_ver VARCHAR(10) NULL,
  agreed_at DATETIME NULL,
  created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
) DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS counselor_applications (
  id INT AUTO_INCREMENT PRIMARY KEY,
  user_id INT NOT NULL,
  intro TEXT NOT NULL,
  status ENUM('pending','approved','rejected') NOT NULL DEFAULT 'pending',
  created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  decided_at DATETIME NULL,
  FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
) DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS consultations (
  id INT AUTO_INCREMENT PRIMARY KEY,
  client_id INT NOT NULL,
  counselor_id INT NULL,
  category VARCHAR(30) NOT NULL,
  title VARCHAR(120) NOT NULL,
  status ENUM('waiting','active','closed') NOT NULL DEFAULT 'waiting',
  created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  closed_at DATETIME NULL,
  FOREIGN KEY (client_id) REFERENCES users(id) ON DELETE CASCADE,
  FOREIGN KEY (counselor_id) REFERENCES users(id) ON DELETE SET NULL,
  INDEX (status)
) DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS messages (
  id INT AUTO_INCREMENT PRIMARY KEY,
  consultation_id INT NOT NULL,
  sender_id INT NOT NULL,
  body TEXT NOT NULL,
  created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (consultation_id) REFERENCES consultations(id) ON DELETE CASCADE,
  FOREIGN KEY (sender_id) REFERENCES users(id) ON DELETE CASCADE,
  INDEX (consultation_id, id)
) DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS email_codes (
  email VARCHAR(190) PRIMARY KEY,
  code_hash CHAR(64) NOT NULL,
  attempts INT NOT NULL DEFAULT 0,
  sent_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  expires_at DATETIME NOT NULL
) DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS passkeys (
  id VARCHAR(1400) CHARACTER SET ascii COLLATE ascii_bin PRIMARY KEY,
  user_id INT NOT NULL,
  public_key BLOB NOT NULL,
  counter BIGINT UNSIGNED NOT NULL DEFAULT 0,
  transports VARCHAR(200) NULL,
  name VARCHAR(60) NOT NULL,
  created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  last_used_at DATETIME NULL,
  FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
  INDEX (user_id)
) DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS counselor_notes (
  consultation_id INT PRIMARY KEY,
  author_id INT NULL,
  body TEXT NOT NULL,
  updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (consultation_id) REFERENCES consultations(id) ON DELETE CASCADE,
  FOREIGN KEY (author_id) REFERENCES users(id) ON DELETE SET NULL
) DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS reviews (
  consultation_id INT PRIMARY KEY,
  client_id INT NOT NULL,
  rating TINYINT NOT NULL,
  body TEXT NULL,
  created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (consultation_id) REFERENCES consultations(id) ON DELETE CASCADE,
  FOREIGN KEY (client_id) REFERENCES users(id) ON DELETE CASCADE
) DEFAULT CHARSET=utf8mb4;

-- 프로필 사진: users 를 매 요청 읽으므로 이미지 바이트는 따로 둔다 (users.avatar 는 내용 해시)
CREATE TABLE IF NOT EXISTS avatars (
  user_id INT PRIMARY KEY,
  mime VARCHAR(20) NOT NULL,
  data MEDIUMBLOB NOT NULL,
  updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
) DEFAULT CHARSET=utf8mb4;

-- 문의 메일 원문 저장본: 받은편지함을 주기적으로 확인해 새 메일을 넣어 두고 화면은 여기서 읽는다
-- 받은 지(received_at) 30일 지난 읽은(seen) 메일은 inbox.js 가 지운다
-- box 별 UID 는 IMAP 폴더의 UIDVALIDITY 가 바뀌면 다른 메일을 가리키므로 함께 남겨 두고, 바뀌면 그 메일함 캐시를 비운다
CREATE TABLE IF NOT EXISTS mail_cache (
  box VARCHAR(10) CHARACTER SET ascii NOT NULL,
  uid INT UNSIGNED NOT NULL,
  uidvalidity BIGINT UNSIGNED NOT NULL,
  source LONGBLOB NOT NULL,
  seen TINYINT(1) NOT NULL DEFAULT 0,
  received_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (box, uid),
  INDEX (received_at)
);

-- 외부 계정 로그인 연결 (지금은 X). subject 는 그 서비스의 고유 사용자 번호, username 은 표시용 아이디
-- 회원 1명당 서비스마다 1개, 외부 계정 1개는 회원 1명에게만 연결된다
CREATE TABLE IF NOT EXISTS social_accounts (
  provider VARCHAR(10) CHARACTER SET ascii NOT NULL,
  subject VARCHAR(64) CHARACTER SET ascii NOT NULL,
  user_id INT NOT NULL,
  username VARCHAR(60) NULL,
  created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (provider, subject),
  UNIQUE KEY user_provider (user_id, provider),
  FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
) DEFAULT CHARSET=utf8mb4;
