const Database = require('better-sqlite3');
const fs = require('fs');
const path = require('path');

const DB_PATH = process.env.DB_PATH || path.join(__dirname, 'freeintelhub.sqlite');
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

// Safe column migration: only adds if missing, logs on success
function addColumn(table, col, def) {
  const exists = db.prepare(`PRAGMA table_info(${table})`).all().some(r => r.name === col);
  if (!exists) {
    db.exec(`ALTER TABLE ${table} ADD COLUMN ${col} ${def}`);
    console.log(`[DB] Migration: added ${table}.${col}`);
  }
}

// Migrations: add columns if missing
addColumn('articles', 'sector', 'TEXT');
addColumn('articles', 'mitre_techniques', 'TEXT');
addColumn('articles', 'iocs', 'TEXT');
addColumn('articles', 'vendors_all', 'TEXT');
addColumn('articles', 'dedup_hash', 'TEXT');

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
addColumn('subscribers', 'verify_token', 'TEXT');

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
  CREATE INDEX IF NOT EXISTS idx_articles_iocs_partial ON articles(published_at DESC) WHERE iocs IS NOT NULL;
  CREATE INDEX IF NOT EXISTS idx_articles_cat_pub ON articles(category, published_at DESC);
  CREATE INDEX IF NOT EXISTS idx_articles_sec_pub ON articles(sector, published_at DESC);
  CREATE INDEX IF NOT EXISTS idx_articles_ven_pub ON articles(vendor, published_at DESC);
`);

// Migration: entity extraction tracking flag
addColumn('articles', 'entities_processed', 'INTEGER DEFAULT 0');

// Migration: TLP classification (WHITE / GREEN / AMBER / RED)
addColumn('articles', 'tlp', "TEXT DEFAULT 'WHITE'");

// FTS5 full-text search index
try {
  db.exec(`CREATE VIRTUAL TABLE IF NOT EXISTS articles_fts USING fts5(title, summary, tokenize='porter unicode61')`);
  db.exec(`CREATE TRIGGER IF NOT EXISTS articles_fts_ai AFTER INSERT ON articles BEGIN INSERT INTO articles_fts(rowid, title, summary) VALUES (new.id, new.title, COALESCE(new.summary, '')); END`);
  // Drop and recreate UPDATE/DELETE triggers to use correct regular-FTS5 syntax (not external-content syntax)
  db.exec(`DROP TRIGGER IF EXISTS articles_fts_au`);
  db.exec(`DROP TRIGGER IF EXISTS articles_fts_ad`);
  db.exec(`CREATE TRIGGER articles_fts_au AFTER UPDATE OF title, summary ON articles BEGIN DELETE FROM articles_fts WHERE rowid = old.id; INSERT INTO articles_fts(rowid, title, summary) VALUES (new.id, new.title, COALESCE(new.summary, '')); END`);
  db.exec(`CREATE TRIGGER articles_fts_ad AFTER DELETE ON articles BEGIN DELETE FROM articles_fts WHERE rowid = old.id; END`);
  // Seed FTS index from existing articles if empty
  const ftsCount = db.prepare(`SELECT COUNT(*) as c FROM articles_fts`).get().c;
  if (ftsCount === 0) {
    const artCount = db.prepare(`SELECT COUNT(*) as c FROM articles`).get().c;
    if (artCount > 0) {
      db.prepare(`INSERT INTO articles_fts(rowid, title, summary) SELECT id, title, COALESCE(summary,'') FROM articles`).run();
      console.log(`[DB] FTS5 index seeded with ${artCount} articles`);
    }
  }
} catch (e) {
  console.warn('[DB] FTS5 unavailable:', e.message);
}

// Entity tables: threat groups, malware/software, campaigns
db.exec(`
  CREATE TABLE IF NOT EXISTS threat_groups (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT UNIQUE NOT NULL,
    type TEXT DEFAULT 'unknown',
    country TEXT,
    description TEXT,
    mitre_group_id TEXT,
    aliases TEXT,
    is_auto_detected INTEGER DEFAULT 0,
    first_seen TEXT,
    created_at TEXT DEFAULT (datetime('now'))
  );

  CREATE TABLE IF NOT EXISTS malware_software (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT UNIQUE NOT NULL,
    type TEXT DEFAULT 'unknown',
    description TEXT,
    aliases TEXT,
    is_auto_detected INTEGER DEFAULT 0,
    first_seen TEXT,
    created_at TEXT DEFAULT (datetime('now'))
  );

  CREATE TABLE IF NOT EXISTS campaigns (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT UNIQUE NOT NULL,
    associated_groups TEXT,
    description TEXT,
    aliases TEXT,
    is_auto_detected INTEGER DEFAULT 0,
    first_seen TEXT,
    created_at TEXT DEFAULT (datetime('now'))
  );

  CREATE TABLE IF NOT EXISTS article_threat_groups (
    article_id INTEGER NOT NULL,
    threat_group_id INTEGER NOT NULL,
    PRIMARY KEY (article_id, threat_group_id),
    FOREIGN KEY (article_id) REFERENCES articles(id) ON DELETE CASCADE,
    FOREIGN KEY (threat_group_id) REFERENCES threat_groups(id) ON DELETE CASCADE
  );

  CREATE TABLE IF NOT EXISTS article_malware_sw (
    article_id INTEGER NOT NULL,
    malware_sw_id INTEGER NOT NULL,
    PRIMARY KEY (article_id, malware_sw_id),
    FOREIGN KEY (article_id) REFERENCES articles(id) ON DELETE CASCADE,
    FOREIGN KEY (malware_sw_id) REFERENCES malware_software(id) ON DELETE CASCADE
  );

  CREATE TABLE IF NOT EXISTS article_campaigns (
    article_id INTEGER NOT NULL,
    campaign_id INTEGER NOT NULL,
    PRIMARY KEY (article_id, campaign_id),
    FOREIGN KEY (article_id) REFERENCES articles(id) ON DELETE CASCADE,
    FOREIGN KEY (campaign_id) REFERENCES campaigns(id) ON DELETE CASCADE
  );
`);

// Entity junction indexes
db.exec(`
  CREATE INDEX IF NOT EXISTS idx_atg_group ON article_threat_groups(threat_group_id);
  CREATE INDEX IF NOT EXISTS idx_amsw_sw ON article_malware_sw(malware_sw_id);
  CREATE INDEX IF NOT EXISTS idx_acamp_camp ON article_campaigns(campaign_id);
  CREATE INDEX IF NOT EXISTS idx_articles_ep ON articles(entities_processed);
`);

// Analyst notes & tagging
db.exec(`
  CREATE TABLE IF NOT EXISTS article_notes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    article_id INTEGER NOT NULL,
    token TEXT NOT NULL,
    note TEXT,
    tag TEXT DEFAULT 'note',
    created_at TEXT DEFAULT (datetime('now')),
    FOREIGN KEY (article_id) REFERENCES articles(id) ON DELETE CASCADE
  );
  CREATE INDEX IF NOT EXISTS idx_notes_article ON article_notes(article_id);
`);

// Custom feed sources (user-managed, not in feeds.json)
db.exec(`
  CREATE TABLE IF NOT EXISTS custom_feeds (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT UNIQUE NOT NULL,
    url TEXT NOT NULL,
    category TEXT,
    enabled INTEGER DEFAULT 1,
    created_at TEXT DEFAULT (datetime('now'))
  );
`);

// API keys for external consumers
db.exec(`
  CREATE TABLE IF NOT EXISTS api_keys (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    key_hash TEXT UNIQUE NOT NULL,
    key_prefix TEXT NOT NULL,
    subscriber_id INTEGER,
    requests_today INTEGER DEFAULT 0,
    last_reset TEXT DEFAULT (date('now')),
    created_at TEXT DEFAULT (datetime('now')),
    FOREIGN KEY (subscriber_id) REFERENCES subscribers(id) ON DELETE SET NULL
  );
`);

// Watchlist for proactive monitoring
db.exec(`
  CREATE TABLE IF NOT EXISTS watchlist (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    token TEXT NOT NULL,
    watch_type TEXT NOT NULL,
    watch_value TEXT NOT NULL,
    created_at TEXT DEFAULT (datetime('now')),
    UNIQUE(token, watch_type, watch_value)
  );
`);

// Paste site monitoring hits
db.exec(`
  CREATE TABLE IF NOT EXISTS paste_hits (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    paste_id TEXT UNIQUE NOT NULL,
    title TEXT,
    content_snippet TEXT,
    source TEXT DEFAULT 'psbdmp',
    keyword TEXT,
    full_url TEXT,
    found_at TEXT DEFAULT (datetime('now'))
  );
`);

// Case management
db.exec(`
  CREATE TABLE IF NOT EXISTS cases (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    title TEXT NOT NULL,
    status TEXT DEFAULT 'open',
    severity TEXT DEFAULT 'medium',
    description TEXT,
    created_by TEXT DEFAULT 'analyst',
    created_at TEXT DEFAULT (datetime('now')),
    updated_at TEXT DEFAULT (datetime('now')),
    closed_at TEXT
  );
  CREATE TABLE IF NOT EXISTS case_articles (
    case_id INTEGER NOT NULL,
    article_id INTEGER NOT NULL,
    added_at TEXT DEFAULT (datetime('now')),
    PRIMARY KEY (case_id, article_id),
    FOREIGN KEY (case_id) REFERENCES cases(id) ON DELETE CASCADE,
    FOREIGN KEY (article_id) REFERENCES articles(id) ON DELETE CASCADE
  );
  CREATE TABLE IF NOT EXISTS case_notes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    case_id INTEGER NOT NULL,
    author TEXT DEFAULT 'analyst',
    note TEXT NOT NULL,
    created_at TEXT DEFAULT (datetime('now')),
    FOREIGN KEY (case_id) REFERENCES cases(id) ON DELETE CASCADE
  );
  CREATE INDEX IF NOT EXISTS idx_cases_status ON cases(status);
  CREATE INDEX IF NOT EXISTS idx_case_articles_case ON case_articles(case_id);
`);

// ── Dark web monitoring tables ────────────────────────────────────────────────
db.exec(`
  CREATE TABLE IF NOT EXISTS dw_gang_list (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    group_name TEXT NOT NULL,
    onion_url TEXT NOT NULL UNIQUE,
    status TEXT,
    fetched_at INTEGER NOT NULL
  );

  CREATE TABLE IF NOT EXISTS darkweb_hits (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    site_name TEXT NOT NULL,
    onion_url TEXT NOT NULL,
    category TEXT NOT NULL,
    title TEXT,
    content_snippet TEXT,
    discovered_at INTEGER NOT NULL,
    severity TEXT DEFAULT 'medium'
  );

  CREATE INDEX IF NOT EXISTS idx_dw_discovered ON darkweb_hits(discovered_at DESC);
  CREATE INDEX IF NOT EXISTS idx_dw_category ON darkweb_hits(category, discovered_at DESC);

  CREATE TABLE IF NOT EXISTS dw_forum_list (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    forum_name TEXT NOT NULL,
    url TEXT NOT NULL UNIQUE,
    status TEXT,
    fetched_at INTEGER NOT NULL
  );
`);

// Migrations: add IOCs and entities_processed columns to darkweb_hits if missing
addColumn('darkweb_hits', 'iocs', 'TEXT');
addColumn('darkweb_hits', 'entities_processed', 'INTEGER DEFAULT 0');

// ── IOC geolocation enrichment ────────────────────────────────────────────────
db.exec(`
  CREATE TABLE IF NOT EXISTS ioc_geo (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ip TEXT UNIQUE NOT NULL,
    country TEXT,
    country_name TEXT,
    lat REAL,
    lon REAL,
    first_seen INTEGER,
    last_seen INTEGER,
    source TEXT,
    article_id INTEGER,
    darkweb_hit_id INTEGER
  );
  CREATE INDEX IF NOT EXISTS idx_ioc_geo_country ON ioc_geo(country);
  CREATE INDEX IF NOT EXISTS idx_ioc_geo_last_seen ON ioc_geo(last_seen DESC);
`);

// AI intelligence brief cache (Gemini-generated summaries, 24h TTL)
db.exec(`
  CREATE TABLE IF NOT EXISTS ai_summaries (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    entity_type TEXT NOT NULL,
    entity_id INTEGER NOT NULL,
    summary_json TEXT NOT NULL,
    generated_at TEXT DEFAULT (datetime('now')),
    UNIQUE(entity_type, entity_id)
  );
  CREATE INDEX IF NOT EXISTS idx_ai_summaries_lookup ON ai_summaries(entity_type, entity_id);
`);

// Users table for authentication
db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    role TEXT DEFAULT 'viewer',
    created_at TEXT DEFAULT (datetime('now')),
    last_login TEXT
  );
`);

// ── Malpedia enrichment columns ───────────────────────────────────────────────
addColumn('malware_software', 'malpedia_slug', 'TEXT');
addColumn('malware_software', 'malpedia_uuid', 'TEXT');
addColumn('malware_software', 'malpedia_refs', 'TEXT');
addColumn('malware_software', 'malpedia_attribution', 'TEXT');
addColumn('threat_groups', 'malpedia_slug', 'TEXT');
addColumn('threat_groups', 'malpedia_uuid', 'TEXT');
addColumn('threat_groups', 'malpedia_refs', 'TEXT');
// Threat actor profiling fields (skill: profiling-threat-actor-groups)
addColumn('threat_groups', 'motivation', 'TEXT');                  // espionage | financial | disruption | ip-theft | unknown
addColumn('threat_groups', 'attribution_confidence', 'TEXT');      // low | medium | high
addColumn('threat_groups', 'targeting_sectors', 'TEXT');           // JSON array of sector strings
addColumn('threat_groups', 'targeting_geographies', 'TEXT');       // JSON array of country/region strings

db.exec(`
  CREATE TABLE IF NOT EXISTS malpedia_sync_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    synced_at TEXT DEFAULT (datetime('now')),
    families_fetched INTEGER,
    actors_fetched INTEGER,
    sw_matched INTEGER,
    tg_matched INTEGER
  )
`);

// ── abuse.ch SSL Blacklist cache ──────────────────────────────────────────────
db.exec(`
  CREATE TABLE IF NOT EXISTS ssl_blacklist (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    sha1 TEXT UNIQUE NOT NULL,
    listing_date TEXT,
    reason TEXT,
    synced_at TEXT DEFAULT (datetime('now'))
  );
  CREATE INDEX IF NOT EXISTS idx_ssl_sha1 ON ssl_blacklist(sha1);
  CREATE TABLE IF NOT EXISTS ssl_sync_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    synced_at TEXT DEFAULT (datetime('now')),
    count INTEGER
  )
`);

// ── CVE enrichment (EPSS score + CISA KEV catalog) ───────────────────────────
db.exec(`
  CREATE TABLE IF NOT EXISTS cve_enrichment (
    cve_id TEXT PRIMARY KEY,
    epss REAL,
    epss_percentile REAL,
    epss_updated_at TEXT,
    on_kev INTEGER DEFAULT 0,
    kev_added_at TEXT,
    kev_due_date TEXT,
    kev_known_ransomware INTEGER DEFAULT 0,
    last_synced_at TEXT DEFAULT (datetime('now'))
  );
  CREATE INDEX IF NOT EXISTS idx_cve_enrichment_kev  ON cve_enrichment(on_kev) WHERE on_kev = 1;
  CREATE INDEX IF NOT EXISTS idx_cve_enrichment_epss ON cve_enrichment(epss DESC);
`);

// ── Audit log (logins, case edits, API key use, admin actions) ───────────────
db.exec(`
  CREATE TABLE IF NOT EXISTS audit_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    actor TEXT,
    action TEXT NOT NULL,
    target_type TEXT,
    target_id TEXT,
    detail TEXT,
    ip TEXT,
    created_at TEXT DEFAULT (datetime('now'))
  );
  CREATE INDEX IF NOT EXISTS idx_audit_log_created ON audit_log(created_at DESC);
  CREATE INDEX IF NOT EXISTS idx_audit_log_actor   ON audit_log(actor, created_at DESC);
`);

// ── Saved searches (per-user persisted filter combos) ────────────────────────
db.exec(`
  CREATE TABLE IF NOT EXISTS saved_searches (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    owner TEXT NOT NULL,
    name TEXT NOT NULL,
    path TEXT NOT NULL,
    query TEXT NOT NULL,
    created_at TEXT DEFAULT (datetime('now')),
    UNIQUE(owner, name)
  );
  CREATE INDEX IF NOT EXISTS idx_saved_owner ON saved_searches(owner);
`);

// API-key scopes (CSV; NULL = legacy "all access")
addColumn('api_keys', 'scopes', 'TEXT');

module.exports = db;
