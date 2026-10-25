DROP TABLE IF EXISTS activity_logs;
DROP TABLE IF EXISTS documents;
DROP TABLE IF EXISTS folders;
DROP TABLE IF EXISTS login_attempts;
DROP TABLE IF EXISTS users;

-- =========================
-- USERS TABLE
-- =========================
CREATE TABLE users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    email TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    phone_number TEXT,
    kyc_verified INTEGER DEFAULT 0,
    role TEXT DEFAULT 'user',
    otp_secret TEXT,                        -- TOTP secret for 2FA
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- =========================
-- LOGIN ATTEMPTS TABLE (rate limiting)
-- =========================
CREATE TABLE login_attempts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email TEXT NOT NULL,
    attempted_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    success INTEGER DEFAULT 0
);

-- =========================
-- FOLDERS TABLE
-- =========================
CREATE TABLE folders (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    name TEXT NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
);

-- =========================
-- DOCUMENTS TABLE
-- =========================
CREATE TABLE documents (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    folder_id INTEGER,                      -- NULL means root/no folder
    doc_type TEXT NOT NULL,
    doc_name TEXT NOT NULL,
    category TEXT DEFAULT 'General',
    favorite INTEGER DEFAULT 0,
    file_mime TEXT,
    file_size_bytes INTEGER,
    file_size_string TEXT,
    file_blob BLOB NOT NULL,                -- stored encrypted
    download_count INTEGER DEFAULT 0,       -- incremented on each download
    uploaded_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE,
    FOREIGN KEY(folder_id) REFERENCES folders(id) ON DELETE SET NULL
);

-- =========================
-- ACTIVITY LOGS TABLE
-- =========================
CREATE TABLE activity_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER,
    action TEXT NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
);
