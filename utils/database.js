const Database = require('better-sqlite3');
const path = require('path');
const db = new Database(path.join(__dirname, '..', 'data.db'));
db.pragma('journal_mode = WAL');
db.pragma('foreign_keys = ON');
db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id TEXT PRIMARY KEY, email TEXT UNIQUE NOT NULL, password_hash TEXT NOT NULL,
    name TEXT, is_pro INTEGER DEFAULT 0, plan TEXT DEFAULT 'free',
    stripe_customer_id TEXT, stripe_subscription_id TEXT,
    subscription_status TEXT DEFAULT 'inactive', subscription_end_date TEXT,
    reset_token TEXT, reset_token_expires TEXT,
    gdpr_consent INTEGER DEFAULT 0, gdpr_consent_date TEXT,
    ai_calls_today INTEGER DEFAULT 0, ai_calls_date TEXT,
    created_at TEXT DEFAULT (datetime('now')), last_seen TEXT DEFAULT (datetime('now'))
  );
  CREATE TABLE IF NOT EXISTS family_members (
    id TEXT PRIMARY KEY, user_id TEXT NOT NULL, name TEXT NOT NULL,
    dob TEXT, weight_kg REAL, conditions TEXT DEFAULT '[]', allergies TEXT DEFAULT '[]',
    is_primary INTEGER DEFAULT 0, created_at TEXT DEFAULT (datetime('now')),
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
  );
  CREATE TABLE IF NOT EXISTS medications (
    id TEXT PRIMARY KEY, user_id TEXT NOT NULL, member_id TEXT NOT NULL,
    name TEXT NOT NULL, generic_name TEXT, dosage TEXT, frequency TEXT,
    purpose TEXT, is_otc INTEGER DEFAULT 0, is_active INTEGER DEFAULT 1,
    image_base64 TEXT, raw_label TEXT, notes TEXT,
    created_at TEXT DEFAULT (datetime('now')),
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    FOREIGN KEY (member_id) REFERENCES family_members(id) ON DELETE CASCADE
  );
  CREATE TABLE IF NOT EXISTS scans (
    id TEXT PRIMARY KEY, user_id TEXT NOT NULL, member_id TEXT,
    drug_name TEXT, result TEXT, created_at TEXT DEFAULT (datetime('now')),
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
  );
  CREATE TABLE IF NOT EXISTS interaction_checks (
    id TEXT PRIMARY KEY, user_id TEXT NOT NULL, member_id TEXT,
    medications TEXT NOT NULL, result TEXT NOT NULL, severity TEXT DEFAULT 'none',
    checked_at TEXT DEFAULT (datetime('now'))
  );
  CREATE TABLE IF NOT EXISTS refresh_tokens (
    id TEXT PRIMARY KEY, user_id TEXT NOT NULL, token_hash TEXT UNIQUE NOT NULL,
    expires_at TEXT NOT NULL, used INTEGER DEFAULT 0, created_at TEXT DEFAULT (datetime('now')),
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
  );
  CREATE TABLE IF NOT EXISTS processed_webhooks (
    id TEXT PRIMARY KEY, processed_at TEXT DEFAULT (datetime('now'))
  );
  CREATE INDEX IF NOT EXISTS idx_meds_member ON medications(member_id,is_active);
  CREATE INDEX IF NOT EXISTS idx_scans_user ON scans(user_id,created_at DESC);
  CREATE INDEX IF NOT EXISTS idx_rt_hash ON refresh_tokens(token_hash);
`);

const userQ = {
  create: db.prepare('INSERT INTO users (id,email,password_hash,name,gdpr_consent,gdpr_consent_date) VALUES (?,?,?,?,?,?)'),
  byEmail: db.prepare('SELECT * FROM users WHERE email=?'),
  byId: db.prepare('SELECT * FROM users WHERE id=?'),
  byResetToken: db.prepare("SELECT * FROM users WHERE reset_token=? AND reset_token_expires > datetime('now')"),
  updateLastSeen: db.prepare("UPDATE users SET last_seen=datetime('now') WHERE id=?"),
  updatePro: db.prepare('UPDATE users SET is_pro=?,plan=?,stripe_customer_id=?,stripe_subscription_id=?,subscription_status=?,subscription_end_date=? WHERE id=?'),
  deactivatePro: db.prepare("UPDATE users SET is_pro=0,plan='free',subscription_status='cancelled' WHERE stripe_subscription_id=?"),
  setResetToken: db.prepare("UPDATE users SET reset_token=?,reset_token_expires=datetime('now','+1 hour') WHERE email=?"),
  clearResetToken: db.prepare('UPDATE users SET reset_token=NULL,reset_token_expires=NULL,password_hash=? WHERE id=?'),
  incrementAiCalls: db.prepare("UPDATE users SET ai_calls_today=CASE WHEN ai_calls_date=date('now') THEN ai_calls_today+1 ELSE 1 END,ai_calls_date=date('now') WHERE id=?"),
};
const memberQ = {
  create: db.prepare('INSERT INTO family_members (id,user_id,name,dob,weight_kg,conditions,allergies,is_primary) VALUES (?,?,?,?,?,?,?,?)'),
  byUser: db.prepare('SELECT * FROM family_members WHERE user_id=? ORDER BY is_primary DESC,name'),
  byId: db.prepare('SELECT * FROM family_members WHERE id=? AND user_id=?'),
  update: db.prepare('UPDATE family_members SET name=?,dob=?,weight_kg=?,conditions=?,allergies=? WHERE id=? AND user_id=?'),
  delete: db.prepare('DELETE FROM family_members WHERE id=? AND user_id=?'),
  count: db.prepare('SELECT COUNT(*) as count FROM family_members WHERE user_id=?'),
};
const medQ = {
  create: db.prepare('INSERT INTO medications (id,user_id,member_id,name,generic_name,dosage,frequency,purpose,is_otc,image_base64,raw_label,notes) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)'),
  byMember: db.prepare('SELECT * FROM medications WHERE member_id=? AND user_id=? AND is_active=1 ORDER BY name'),
  byId: db.prepare('SELECT * FROM medications WHERE id=? AND user_id=?'),
  update: db.prepare('UPDATE medications SET name=?,generic_name=?,dosage=?,frequency=?,notes=?,is_active=? WHERE id=? AND user_id=?'),
  delete: db.prepare('DELETE FROM medications WHERE id=? AND user_id=?'),
  deactivate: db.prepare('UPDATE medications SET is_active=0 WHERE id=? AND user_id=?'),
};
const scanQ = {
  create: db.prepare('INSERT INTO scans (id,user_id,member_id,drug_name,result) VALUES (?,?,?,?,?)'),
  freeCount: db.prepare("SELECT COUNT(*) as count FROM scans WHERE user_id=? AND created_at > datetime('now','-30 days')"),
  recent: db.prepare('SELECT * FROM scans WHERE user_id=? ORDER BY created_at DESC LIMIT 20'),
};
const checkQ = {
  create: db.prepare('INSERT INTO interaction_checks (id,user_id,member_id,medications,result,severity) VALUES (?,?,?,?,?,?)'),
  byMember: db.prepare('SELECT * FROM interaction_checks WHERE member_id=? AND user_id=? ORDER BY checked_at DESC LIMIT 5'),
};
const webhookQ = {
  seen: db.prepare('SELECT id FROM processed_webhooks WHERE id=?'),
  record: db.prepare('INSERT OR IGNORE INTO processed_webhooks (id) VALUES (?)'),
};
const rtQ = {
  create: db.prepare('INSERT INTO refresh_tokens (id,user_id,token_hash,expires_at) VALUES (?,?,?,?)'),
  find: db.prepare("SELECT * FROM refresh_tokens WHERE token_hash=? AND used=0 AND expires_at > datetime('now')"),
  use: db.prepare('UPDATE refresh_tokens SET used=1 WHERE id=?'),
  revokeAll: db.prepare('UPDATE refresh_tokens SET used=1 WHERE user_id=?'),
};
module.exports = { db, userQ, memberQ, medQ, scanQ, checkQ, webhookQ, rtQ };
