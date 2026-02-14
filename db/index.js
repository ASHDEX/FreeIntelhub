const Database = require('better-sqlite3');
const path = require('path');

const DB_PATH = path.join(__dirname, 'freeintelhub.sqlite');
const db = new Database(DB_PATH);

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

// Migration: add sector column if missing
try { db.exec(`ALTER TABLE articles ADD COLUMN sector TEXT`); } catch (_) {}

// Indexes (after migrations so all columns exist)
db.exec(`
  CREATE INDEX IF NOT EXISTS idx_articles_published ON articles(published_at DESC);
  CREATE INDEX IF NOT EXISTS idx_articles_vendor ON articles(vendor);
  CREATE INDEX IF NOT EXISTS idx_articles_category ON articles(category);
  CREATE INDEX IF NOT EXISTS idx_articles_source ON articles(source);
  CREATE INDEX IF NOT EXISTS idx_articles_sector ON articles(sector);
`);

module.exports = db;
