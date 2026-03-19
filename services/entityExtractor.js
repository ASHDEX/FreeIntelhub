/**
 * Entity Extractor
 * Detects threat groups, malware/software, and campaigns in article text.
 * Phase 1: Alias matching against DB-seeded known entities.
 * Phase 2: Pattern-based auto-discovery of new entities.
 * New entities are persisted to DB and accumulate over time.
 */

const db = require('../db');

// ── Auto-discovery patterns ───────────────────────────────────────────────────

// Threat group patterns — ordered by confidence
const TG_PATTERNS = [
  // Structured identifiers (very high confidence)
  { re: /\b(APT[-\s]?\d+)\b/g,  norm: s => s.replace(/\s/, '-').toUpperCase() },
  { re: /\b(TA\d{3,4})\b/g,     norm: s => s.toUpperCase() },
  { re: /\b(UNC\d{4})\b/g,      norm: s => s.toUpperCase() },
  { re: /\b(FIN\d{1,2})\b/g,    norm: s => s.toUpperCase() },
  // Named group descriptors — require title-case lead word
  { re: /\b([A-Z][a-zA-Z0-9]+(?:\s[A-Z][a-zA-Z0-9]+)?)\s+(?:Gang|Group|Team|Collective|Operators?|Crew)\b/g, norm: s => s.trim() },
];

// Malware/software type map — keyword → stored type
const MSW_TYPE_MAP = {
  ransomware: 'ransomware', rat: 'rat',     stealer: 'stealer',
  infostealer: 'stealer',  loader: 'loader', dropper: 'loader',
  backdoor: 'backdoor',    rootkit: 'rootkit', trojan: 'trojan',
  botnet: 'botnet',        wiper: 'wiper',   spyware: 'spyware',
  keylogger: 'keylogger',  implant: 'backdoor', malware: 'unknown',
};

const MSW_PATTERNS = [
  // "[Name] RAT" — uppercase-only suffix, separate pattern
  { re: /\b([A-Z][a-zA-Z0-9]+(?:[\-.][A-Z][a-zA-Z0-9]+)*)\s+RAT\b/g, type: 'rat' },
  // "[Name] <keyword>" — title-case name ONLY (no 'i' flag so [A-Z] enforces capital lead)
  ...Object.entries(MSW_TYPE_MAP).map(([kw, type]) => ({
    re: new RegExp(`\\b([A-Z][a-zA-Z0-9]+(?:[\\-.][A-Z][a-zA-Z0-9]+)*)\\s+${kw}\\b`, 'g'),
    type,
  })),
];

// Campaign patterns — keep full canonical name
const CAMP_PATTERNS = [
  /\bOperation\s+([A-Z][A-Za-z0-9]+(?:\s+[A-Z][A-Za-z0-9]+)?)\b/g,
];

// ── Stoplists ─────────────────────────────────────────────────────────────────

const TG_STOP = new Set([
  'threat', 'cyber', 'hacking', 'attack', 'nation', 'state', 'advanced',
  'persistent', 'unknown', 'new', 'the', 'this', 'that', 'some', 'any',
  'criminal', 'hacktivist', 'north', 'south', 'east', 'west', 'chinese',
  'russian', 'iranian', 'korean', 'american', 'global', 'security',
  'research', 'intelligence', 'federal', 'national', 'ransomware',
]);

const MSW_STOP = new Set([
  // Articles & determiners
  'a', 'an', 'the', 'this', 'that', 'these', 'those', 'such',
  // Conjunctions
  'and', 'or', 'but', 'nor', 'so', 'yet', 'for', 'both', 'either', 'neither',
  'whether', 'although', 'because', 'since', 'unless', 'until', 'while',
  // Prepositions
  'in', 'on', 'at', 'by', 'to', 'of', 'up', 'via', 'with', 'from',
  'into', 'onto', 'over', 'under', 'after', 'before', 'behind', 'between',
  'through', 'during', 'about', 'against', 'among', 'around', 'below',
  'beside', 'beyond', 'except', 'inside', 'outside', 'toward', 'within', 'without',
  // Pronouns
  'it', 'its', 'they', 'their', 'them', 'we', 'our', 'you', 'your',
  'he', 'she', 'his', 'her', 'who', 'which', 'what', 'when', 'where',
  // Quantifiers / indefinites
  'some', 'any', 'all', 'each', 'every', 'few', 'more', 'most', 'other',
  'another', 'same', 'both', 'several', 'many', 'much', 'less',
  'only', 'just', 'even', 'also', 'very', 'well', 'still', 'too',
  // Common adjectives
  'new', 'old', 'big', 'small', 'large', 'high', 'low', 'long', 'short',
  'fast', 'slow', 'hard', 'easy', 'full', 'dark', 'light', 'hot', 'cold',
  'true', 'false', 'real', 'live', 'dead', 'good', 'bad', 'best', 'worse',
  'first', 'last', 'next', 'main', 'public', 'private', 'local', 'remote',
  // Common verbs
  'use', 'get', 'set', 'run', 'put', 'let', 'try', 'say', 'see', 'ask',
  'add', 'end', 'fix', 'hit', 'cut', 'pay', 'win', 'sit', 'stay', 'play',
  'move', 'pull', 'push', 'send', 'read', 'write', 'call', 'keep', 'make',
  'take', 'give', 'find', 'show', 'help', 'stop', 'start', 'check', 'allow',
  'block', 'drop', 'open', 'close', 'load', 'save', 'scan', 'search',
  'build', 'create', 'delete', 'enable', 'disable', 'install', 'update',
  // CTI-domain generic terms
  'custom', 'unknown', 'advanced', 'critical', 'major', 'latest', 'recent',
  'common', 'popular', 'dangerous', 'sophisticated', 'targeted', 'novel',
  'zero', 'multiple', 'suspected', 'potential', 'known', 'hidden',
  'payload', 'exploit', 'attack', 'script', 'code', 'file', 'data', 'tool',
  'service', 'system', 'network', 'server', 'client', 'host', 'user', 'admin',
  'base', 'core', 'manager', 'module', 'plugin', 'agent', 'driver', 'process',
  // Nationalities / geography
  'north', 'south', 'east', 'west', 'chinese', 'russian', 'iranian', 'korean',
  'american', 'global', 'national', 'federal', 'government', 'healthcare',
  // Platforms / modifiers
  'windows', 'linux', 'android', 'mobile', 'banking', 'financial', 'corporate',
  'industrial', 'open', 'source', 'free', 'commercial', 'legitimate', 'modified',
  // Misc high-FP words
  'security', 'research', 'intelligence', 'criminal', 'hacktivist',
]);

// ── In-memory alias cache ─────────────────────────────────────────────────────

let _cache = null;
let _cacheTs = 0;
const CACHE_TTL = 5 * 60 * 1000; // 5 minutes

function loadCache() {
  if (_cache && Date.now() - _cacheTs < CACHE_TTL) return _cache;

  const tgMap  = new Map(); // lowercase alias → { id, name }
  const mswMap = new Map();
  const campMap = new Map();

  for (const row of db.prepare('SELECT id, name, aliases FROM threat_groups').all()) {
    const aliases = row.aliases ? JSON.parse(row.aliases) : [];
    for (const a of [row.name, ...aliases]) tgMap.set(a.toLowerCase(), { id: row.id, name: row.name });
  }
  for (const row of db.prepare('SELECT id, name, aliases FROM malware_software').all()) {
    const aliases = row.aliases ? JSON.parse(row.aliases) : [];
    for (const a of [row.name, ...aliases]) mswMap.set(a.toLowerCase(), { id: row.id, name: row.name });
  }
  for (const row of db.prepare('SELECT id, name, aliases FROM campaigns').all()) {
    const aliases = row.aliases ? JSON.parse(row.aliases) : [];
    for (const a of [row.name, ...aliases]) campMap.set(a.toLowerCase(), { id: row.id, name: row.name });
  }

  _cache = { tgMap, mswMap, campMap };
  _cacheTs = Date.now();
  return _cache;
}

function invalidateCache() { _cache = null; }

// ── Prepared statements ───────────────────────────────────────────────────────

const stmts = {
  upsertTG: db.prepare(`
    INSERT INTO threat_groups (name, type, is_auto_detected, first_seen)
    VALUES (?, 'unknown', 1, datetime('now'))
    ON CONFLICT(name) DO NOTHING
  `),
  upsertMSW: db.prepare(`
    INSERT INTO malware_software (name, type, is_auto_detected, first_seen)
    VALUES (?, ?, 1, datetime('now'))
    ON CONFLICT(name) DO NOTHING
  `),
  upsertCamp: db.prepare(`
    INSERT INTO campaigns (name, is_auto_detected, first_seen)
    VALUES (?, 1, datetime('now'))
    ON CONFLICT(name) DO NOTHING
  `),
  getTG:   db.prepare('SELECT id FROM threat_groups WHERE name = ?'),
  getMSW:  db.prepare('SELECT id FROM malware_software WHERE name = ?'),
  getCamp: db.prepare('SELECT id FROM campaigns WHERE name = ?'),

  linkTG:   db.prepare('INSERT OR IGNORE INTO article_threat_groups (article_id, threat_group_id) VALUES (?, ?)'),
  linkMSW:  db.prepare('INSERT OR IGNORE INTO article_malware_sw (article_id, malware_sw_id) VALUES (?, ?)'),
  linkCamp: db.prepare('INSERT OR IGNORE INTO article_campaigns (article_id, campaign_id) VALUES (?, ?)'),

  seedTG: db.prepare(`
    INSERT INTO threat_groups (name, type, country, description, mitre_group_id, aliases, is_auto_detected, first_seen)
    VALUES (@name, @type, @country, @description, @mitre_group_id, @aliases, 0, '2020-01-01')
    ON CONFLICT(name) DO UPDATE SET
      type           = excluded.type,
      country        = excluded.country,
      description    = COALESCE(threat_groups.description, excluded.description),
      mitre_group_id = COALESCE(threat_groups.mitre_group_id, excluded.mitre_group_id),
      aliases        = excluded.aliases,
      is_auto_detected = 0
  `),
  seedMSW: db.prepare(`
    INSERT INTO malware_software (name, type, description, aliases, is_auto_detected, first_seen)
    VALUES (@name, @type, @description, @aliases, 0, '2020-01-01')
    ON CONFLICT(name) DO UPDATE SET
      type        = excluded.type,
      description = COALESCE(malware_software.description, excluded.description),
      aliases     = excluded.aliases,
      is_auto_detected = 0
  `),
  seedCamp: db.prepare(`
    INSERT INTO campaigns (name, associated_groups, description, aliases, is_auto_detected, first_seen)
    VALUES (@name, @associated_groups, @description, @aliases, 0, @first_seen)
    ON CONFLICT(name) DO UPDATE SET
      associated_groups = excluded.associated_groups,
      description       = COALESCE(campaigns.description, excluded.description),
      aliases           = excluded.aliases,
      is_auto_detected  = 0
  `),

  markProcessed: db.prepare('UPDATE articles SET entities_processed = 1 WHERE id = ?'),
};

// ── Seeding from config files ─────────────────────────────────────────────────

function seedEntities() {
  const tgData   = require('../config/threatgroups.json');
  const mswData  = require('../config/software.json');
  const campData = require('../config/campaigns.json');

  db.transaction(() => {
    for (const tg of tgData) {
      stmts.seedTG.run({
        name: tg.name,
        type: tg.type || 'unknown',
        country: tg.country || null,
        description: tg.description || null,
        mitre_group_id: tg.mitre_group_id || null,
        aliases: JSON.stringify(tg.aliases || []),
      });
    }
    for (const ms of mswData) {
      stmts.seedMSW.run({
        name: ms.name,
        type: ms.type || 'unknown',
        description: ms.description || null,
        aliases: JSON.stringify(ms.aliases || []),
      });
    }
    for (const camp of campData) {
      stmts.seedCamp.run({
        name: camp.name,
        associated_groups: JSON.stringify(camp.associated_groups || []),
        description: camp.description || null,
        aliases: JSON.stringify(camp.aliases || []),
        first_seen: camp.first_seen || '2020-01-01',
      });
    }
  })();

  invalidateCache();
  console.log(`[Entities] Seeded ${tgData.length} threat groups, ${mswData.length} software, ${campData.length} campaigns.`);
}

// ── Structural validator for Phase-2 auto-detected software names ─────────────
//
// Real malware/tool names have at least one technical signal:
//   • CamelCase internal uppercase  → LockBit, SmokeLoader, DarkGate, WannaCry
//   • A digit                       → Gh0st, X509, TrickBot2
//   • A hyphen or dot               → X-Agent, Poison.Ivy, AsyncRAT-ng
//
// Plain single-case English words ("Advanced", "Microsoft", "Critical")
// have none of these and are rejected as false positives.
// Phase 1 (alias matching) still catches known names like "Mirai" or "Ryuk"
// because they are seeded from MITRE/Malpedia before reaching Phase 2.
//
function looksLikeSoftwareName(name) {
  return /[a-z][A-Z]/.test(name)  // camelCase: LockBit, SmokeLoader, DarkGate
      || /\d/.test(name)           // digit:     Gh0st, X509, NjRAT2
      || /[-.]/.test(name);        // separator: X-Agent, Poison.Ivy
}

// ── Core extraction ───────────────────────────────────────────────────────────

function extractEntities(text) {
  if (!text) return { threatGroups: [], malwareSw: [], campaigns: [] };

  const { tgMap, mswMap, campMap } = loadCache();
  const lower = text.toLowerCase();

  const tgIds   = new Set();
  const mswIds  = new Set();
  const campIds = new Set();

  // Phase 1: match known entities by alias (substring scan)
  for (const [alias, entity] of tgMap)   if (lower.includes(alias)) tgIds.add(entity.id);
  for (const [alias, entity] of mswMap)  if (lower.includes(alias)) mswIds.add(entity.id);
  for (const [alias, entity] of campMap) if (lower.includes(alias)) campIds.add(entity.id);

  // Phase 2: pattern-based auto-discovery
  let cacheInvalidated = false;

  // Threat groups
  for (const { re, norm } of TG_PATTERNS) {
    re.lastIndex = 0;
    let m;
    while ((m = re.exec(text)) !== null) {
      const name = norm ? norm(m[1]) : m[1].trim();
      if (name.length < 3) continue;
      if (TG_STOP.has(name.toLowerCase())) continue;
      const lc = name.toLowerCase();
      if (tgMap.has(lc)) { tgIds.add(tgMap.get(lc).id); continue; }
      const tgInfo = stmts.upsertTG.run(name);
      if (tgInfo.changes > 0) {
        tgIds.add(tgInfo.lastInsertRowid); cacheInvalidated = true;
      } else {
        const row = stmts.getTG.get(name);
        if (row) tgIds.add(row.id);
      }
    }
  }

  // Malware/software
  for (const { re, type } of MSW_PATTERNS) {
    re.lastIndex = 0;
    let m;
    while ((m = re.exec(text)) !== null) {
      const name = m[1].trim();
      if (name.length < 4) continue;
      if (MSW_STOP.has(name.toLowerCase())) continue;
      const lc = name.toLowerCase();
      if (mswMap.has(lc)) { mswIds.add(mswMap.get(lc).id); continue; }
      // Phase-2 gate: only auto-create if name has a technical structure signal
      if (!looksLikeSoftwareName(name)) continue;
      const mswInfo = stmts.upsertMSW.run(name, type);
      if (mswInfo.changes > 0) {
        mswIds.add(mswInfo.lastInsertRowid); cacheInvalidated = true;
      } else {
        const row = stmts.getMSW.get(name);
        if (row) mswIds.add(row.id);
      }
    }
  }

  // Campaigns
  for (const re of CAMP_PATTERNS) {
    re.lastIndex = 0;
    let m;
    while ((m = re.exec(text)) !== null) {
      const name = `Operation ${m[1].trim()}`;
      if (name.length < 12) continue; // "Operation X" is too short
      const lc = name.toLowerCase();
      if (campMap.has(lc)) { campIds.add(campMap.get(lc).id); continue; }
      const campInfo = stmts.upsertCamp.run(name);
      if (campInfo.changes > 0) {
        campIds.add(campInfo.lastInsertRowid); cacheInvalidated = true;
      } else {
        const row = stmts.getCamp.get(name);
        if (row) campIds.add(row.id);
      }
    }
  }

  if (cacheInvalidated) invalidateCache();

  return {
    threatGroups: [...tgIds],
    malwareSw:    [...mswIds],
    campaigns:    [...campIds],
  };
}

// ── Link article entities (transactional) ─────────────────────────────────────

const linkArticle = db.transaction((articleId, { threatGroups, malwareSw, campaigns }) => {
  for (const id of threatGroups) stmts.linkTG.run(articleId, id);
  for (const id of malwareSw)    stmts.linkMSW.run(articleId, id);
  for (const id of campaigns)    stmts.linkCamp.run(articleId, id);
  stmts.markProcessed.run(articleId);
});

// ── Backfill existing articles ────────────────────────────────────────────────

function backfillEntities() {
  const unprocessed = db.prepare(`
    SELECT id, title, summary FROM articles
    WHERE entities_processed = 0
    LIMIT 2000
  `).all();

  if (unprocessed.length === 0) {
    console.log('[Entities] Backfill: all articles up to date.');
    return;
  }

  console.log(`[Entities] Backfilling ${unprocessed.length} articles...`);

  // Process in batches to avoid long-running transactions
  const BATCH = 100;
  for (let i = 0; i < unprocessed.length; i += BATCH) {
    const batch = unprocessed.slice(i, i + BATCH);
    db.transaction(() => {
      for (const article of batch) {
        const text = `${article.title || ''} ${article.summary || ''}`;
        linkArticle(article.id, extractEntities(text));
      }
    })();
  }

  console.log('[Entities] Backfill complete.');
}

module.exports = { extractEntities, linkArticle, seedEntities, backfillEntities, invalidateCache };
