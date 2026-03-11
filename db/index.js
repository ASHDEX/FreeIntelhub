const Database = require('better-sqlite3');
const fs = require('fs');
const path = require('path');

const DB_PATH = path.join(__dirname, 'freeintelhub.sqlite');
const db = new Database(DB_PATH);

// Set restrictive file permissions (owner read/write only)
try { fs.chmodSync(DB_PATH, 0o600); } catch (_) {}

// Performance settings
db.pragma('journal_mode = WAL');
db.pragma('foreign_keys = ON');

// Schema
db.exec(`
  CREATE TABLE IF NOT EXISTS articles (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    title TEXT NOT NULL,
    link TEXT UNIQUE NOT NULL,
    summary TEXT,
    source TEXT NOT NULL,
    category TEXT,
    vendor TEXT,
    published_at TEXT,
    created_at TEXT DEFAULT (datetime('now'))
  );

  CREATE TABLE IF NOT EXISTS feed_health (
    source TEXT PRIMARY KEY,
    url TEXT NOT NULL,
    last_status TEXT DEFAULT 'pending',
    last_checked_at TEXT,
    success_count INTEGER DEFAULT 0,
    fail_count INTEGER DEFAULT 0
  );
`);

// Migrations: add columns if missing
try { db.exec(`ALTER TABLE articles ADD COLUMN sector TEXT`); } catch (_) {}
try { db.exec(`ALTER TABLE articles ADD COLUMN mitre_techniques TEXT`); } catch (_) {}
try { db.exec(`ALTER TABLE articles ADD COLUMN iocs TEXT`); } catch (_) {}
try { db.exec(`ALTER TABLE articles ADD COLUMN vendors_all TEXT`); } catch (_) {}
try { db.exec(`ALTER TABLE articles ADD COLUMN dedup_hash TEXT`); } catch (_) {}

// Subscribers & alerts
db.exec(`
  CREATE TABLE IF NOT EXISTS subscribers (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email TEXT UNIQUE NOT NULL,
    daily_newsletter INTEGER DEFAULT 0,
    verified INTEGER DEFAULT 0,
    token TEXT,
    verify_token TEXT,
    created_at TEXT DEFAULT (datetime('now'))
  );

  CREATE TABLE IF NOT EXISTS alert_rules (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    subscriber_id INTEGER NOT NULL,
    rule_type TEXT NOT NULL,
    rule_value TEXT NOT NULL,
    created_at TEXT DEFAULT (datetime('now')),
    FOREIGN KEY (subscriber_id) REFERENCES subscribers(id) ON DELETE CASCADE,
    UNIQUE(subscriber_id, rule_type, rule_value)
  );

  CREATE TABLE IF NOT EXISTS sent_alerts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    subscriber_id INTEGER NOT NULL,
    article_id INTEGER NOT NULL,
    sent_at TEXT DEFAULT (datetime('now')),
    FOREIGN KEY (subscriber_id) REFERENCES subscribers(id) ON DELETE CASCADE,
    FOREIGN KEY (article_id) REFERENCES articles(id) ON DELETE CASCADE,
    UNIQUE(subscriber_id, article_id)
  );
`);

// Migrations: add columns for existing DBs
try { db.exec(`ALTER TABLE subscribers ADD COLUMN verify_token TEXT`); } catch (_) {}

// Webhooks table for Slack/Discord/Telegram/custom integrations
db.exec(`
  CREATE TABLE IF NOT EXISTS webhooks (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    subscriber_id INTEGER NOT NULL,
    webhook_type TEXT NOT NULL,
    webhook_url TEXT NOT NULL,
    created_at TEXT DEFAULT (datetime('now')),
    FOREIGN KEY (subscriber_id) REFERENCES subscribers(id) ON DELETE CASCADE,
    UNIQUE(subscriber_id, webhook_type, webhook_url)
  );
`);

// Bookmarks table
db.exec(`
  CREATE TABLE IF NOT EXISTS bookmarks (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    subscriber_id INTEGER NOT NULL,
    article_id INTEGER NOT NULL,
    created_at TEXT DEFAULT (datetime('now')),
    FOREIGN KEY (subscriber_id) REFERENCES subscribers(id) ON DELETE CASCADE,
    FOREIGN KEY (article_id) REFERENCES articles(id) ON DELETE CASCADE,
    UNIQUE(subscriber_id, article_id)
  );
`);

// Indexes (after migrations so all columns exist)
db.exec(`
  CREATE INDEX IF NOT EXISTS idx_articles_published ON articles(published_at DESC);
  CREATE INDEX IF NOT EXISTS idx_articles_vendor ON articles(vendor);
  CREATE INDEX IF NOT EXISTS idx_articles_category ON articles(category);
  CREATE INDEX IF NOT EXISTS idx_articles_source ON articles(source);
  CREATE INDEX IF NOT EXISTS idx_articles_sector ON articles(sector);
  CREATE INDEX IF NOT EXISTS idx_articles_dedup ON articles(dedup_hash);
`);

module.exports = db;
