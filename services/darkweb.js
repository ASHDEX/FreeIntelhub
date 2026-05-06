'use strict';

/**
 * Dark Web Monitoring Service
 *
 * Fetches and stores data from .onion sites for threat intelligence purposes.
 *
 * ┌─────────────────────────────────────────────────────────────────────┐
 * │  TOR SETUP — REQUIRED before enabling dark web scans                │
 * │                                                                     │
 * │  Install and start the Tor daemon:                                  │
 * │    macOS:   brew install tor && brew services start tor             │
 * │    Ubuntu:  apt install tor && systemctl start tor                  │
 * │                                                                     │
 * │  Tor listens on 127.0.0.1:9050 (SOCKS5) by default.               │
 * │  The app connects through it automatically — no torsocks needed.    │
 * │                                                                     │
 * │  Override proxy: TOR_SOCKS_PROXY=socks5h://127.0.0.1:9050         │
 * └─────────────────────────────────────────────────────────────────────┘
 *
 * Ransomware gang list is sourced from:
 *   https://github.com/fastfire/deepdarkCTI/blob/main/ransomware_gang.md
 * (public threat intelligence repository, cached 24h in dw_gang_list table)
 *
 * Custom sites are configured via DW_MONITORED_SITES env var:
 *   Format: "Name|http://xxx.onion|category" (comma-separated)
 *   Categories: paste | forum | custom
 */

const http  = require('http');
const https = require('https');
const db = require('../db');
const { load } = require('cheerio');
const { SocksProxyAgent } = require('socks-proxy-agent');

// Tor SOCKS5 proxy — socks5h:// means the proxy resolves hostnames (no DNS leak)
const TOR_PROXY = process.env.TOR_SOCKS_PROXY || 'socks5h://127.0.0.1:9050';

const DEEPDARKCTI_URL =
  'https://raw.githubusercontent.com/fastfire/deepdarkCTI/main/ransomware_gang.md';
const DEEPDARKCTI_FORUM_URL =
  'https://raw.githubusercontent.com/fastfire/deepdarkCTI/main/forum.md';

const GANG_LIST_TTL_MS  = 24 * 60 * 60 * 1000; // 24 hours
const FORUM_LIST_TTL_MS = 24 * 60 * 60 * 1000; // 24 hours

// ── DB prepared statements ────────────────────────────────────────────────────

const stmts = {
  upsertGang: db.prepare(`
    INSERT INTO dw_gang_list (group_name, onion_url, status, fetched_at)
    VALUES (@group_name, @onion_url, @status, @fetched_at)
    ON CONFLICT(onion_url) DO UPDATE SET
      group_name = excluded.group_name,
      status     = excluded.status,
      fetched_at = excluded.fetched_at
  `),
  gangCount:  db.prepare(`SELECT COUNT(*) AS count FROM dw_gang_list`),
  gangList:   db.prepare(`SELECT * FROM dw_gang_list ORDER BY group_name ASC`),
  lastFetch:  db.prepare(`SELECT MAX(fetched_at) AS ts FROM dw_gang_list`),

  insertHit: db.prepare(`
    INSERT INTO darkweb_hits (site_name, onion_url, category, title, content_snippet, discovered_at, severity)
    VALUES (@site_name, @onion_url, @category, @title, @content_snippet, @discovered_at, @severity)
  `),
  existsHit: db.prepare(`
    SELECT id FROM darkweb_hits WHERE onion_url = @onion_url AND title = @title LIMIT 1
  `),
  recentHits: db.prepare(`
    SELECT * FROM darkweb_hits ORDER BY discovered_at DESC LIMIT @limit OFFSET @offset
  `),
  recentByCat: db.prepare(`
    SELECT * FROM darkweb_hits WHERE category = @category ORDER BY discovered_at DESC LIMIT @limit OFFSET @offset
  `),
  countAll:   db.prepare(`SELECT COUNT(*) AS count FROM darkweb_hits`),
  countByCat: db.prepare(`SELECT COUNT(*) AS count FROM darkweb_hits WHERE category = @category`),

  upsertForum: db.prepare(`
    INSERT INTO dw_forum_list (forum_name, url, status, fetched_at)
    VALUES (@forum_name, @url, @status, @fetched_at)
    ON CONFLICT(url) DO UPDATE SET
      forum_name = excluded.forum_name,
      status     = excluded.status,
      fetched_at = excluded.fetched_at
  `),
  forumCount:     db.prepare(`SELECT COUNT(*) AS count FROM dw_forum_list`),
  forumList:      db.prepare(`SELECT * FROM dw_forum_list ORDER BY forum_name ASC`),
  forumLastFetch: db.prepare(`SELECT MAX(fetched_at) AS ts FROM dw_forum_list`),
};

// ── deepdarkCTI gang list sync ────────────────────────────────────────────────

/**
 * Parse the deepdarkCTI ransomware_gang.md markdown table.
 *
 * Actual column format: Name (markdown link) | Status | User:Password | Tox ID | RSS Feed
 * The URL is embedded inside the Name cell as [Display Name](url).
 * Both clearnet and .onion URLs appear; we keep only .onion ones.
 *
 * Returns array of { group_name, onion_url, status }
 */
function parseGangMarkdown(md) {
  const results = [];
  const lines = md.split('\n');

  let colName   = -1;
  let colStatus = -1;
  let headerFound = false;

  for (const raw of lines) {
    const line = raw.trim();
    if (!line.startsWith('|')) continue;

    // Split on | but preserve markdown link content — can't just split naively if URL has |
    // Simple approach: split on | then re-join cells that are inside ()
    const cells = line.split('|').map(c => c.trim()).filter((_, i, a) => i > 0 && i < a.length - 1);
    if (cells.length === 0) continue;

    if (!headerFound) {
      const lower = cells.map(c => c.toLowerCase());
      const ni = lower.findIndex(c => c.includes('name') || c.includes('group') || c.includes('gang'));
      const si = lower.findIndex(c => c.includes('status'));
      if (ni !== -1) {
        colName = ni; colStatus = si;
        headerFound = true;
      }
      continue;
    }

    // Skip separator rows (---|---| pattern)
    if (cells.every(c => /^[-: ]+$/.test(c))) continue;
    if (cells.length <= colName) continue;

    const nameCell = cells[colName] || '';

    // Extract display text and URL from markdown link: [text](url)
    const linkMatch = nameCell.match(/^\[([^\]]+)\]\(([^)]+)\)/);
    if (!linkMatch) continue;

    const displayName = linkMatch[1].trim();
    const rawUrl      = linkMatch[2].trim();

    // Only keep .onion URLs
    if (!rawUrl.includes('.onion')) continue;

    // Normalize: ensure http:// prefix (some entries omit it or use bare hostname)
    const onionUrl = /^https?:\/\//.test(rawUrl) ? rawUrl : `http://${rawUrl}`;

    const status = colStatus >= 0 && cells.length > colStatus
      ? (cells[colStatus] || null)
      : null;

    results.push({ group_name: displayName, onion_url: onionUrl, status });
  }

  return results;
}

/**
 * Fetch the deepdarkCTI ransomware gang list and cache it.
 * Skips if the cache is less than GANG_LIST_TTL_MS old.
 * Returns { synced: N, skipped: true|false }
 */
async function syncGangList(force = false) {
  if (!force) {
    const { ts } = stmts.lastFetch.get();
    if (ts && Date.now() - ts < GANG_LIST_TTL_MS) {
      return { synced: stmts.gangCount.get().count, skipped: true };
    }
  }

  let text;
  try {
    const resp = await fetch(DEEPDARKCTI_URL, {
      signal: AbortSignal.timeout(15000),
      headers: { 'User-Agent': 'FreeIntelHub/1.0 (CTI research)' },
    });
    if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
    text = await resp.text();
  } catch (err) {
    console.error('[darkweb] syncGangList fetch error:', err.message);
    return { synced: 0, error: err.message };
  }

  const gangs = parseGangMarkdown(text);
  if (gangs.length === 0) {
    console.warn('[darkweb] syncGangList: parsed 0 entries — format may have changed');
    return { synced: 0, error: 'Parsed 0 entries' };
  }

  const now = Date.now();
  const upsertMany = db.transaction(rows => {
    for (const row of rows) stmts.upsertGang.run({ ...row, fetched_at: now });
  });
  upsertMany(gangs);

  console.log(`[darkweb] syncGangList: synced ${gangs.length} ransomware groups`);
  return { synced: gangs.length, skipped: false };
}

// ── deepdarkCTI forum list sync ───────────────────────────────────────────────

/**
 * Parse the deepdarkCTI forum.md markdown table.
 * Columns: Name (markdown link) | Status | Description
 * Keeps both .onion and clearnet URLs (unlike gang list which is .onion only).
 * Returns array of { forum_name, url, status }
 */
function parseForumMarkdown(md) {
  const results = [];
  const lines = md.split('\n');
  let headerFound = false;

  for (const raw of lines) {
    const line = raw.trim();
    if (!line.startsWith('|')) continue;
    const cells = line.split('|').map(c => c.trim()).filter((_, i, a) => i > 0 && i < a.length - 1);
    if (cells.length === 0) continue;

    if (!headerFound) {
      if (cells.map(c => c.toLowerCase()).some(c => c.includes('name'))) {
        headerFound = true;
      }
      continue;
    }

    if (cells.every(c => /^[-: ]+$/.test(c))) continue;

    const nameCell = cells[0] || '';
    const linkMatch = nameCell.match(/^\[([^\]]+)\]\(([^)]+)\)/);
    if (!linkMatch) continue;

    const forum_name = linkMatch[1].trim();
    const rawUrl     = linkMatch[2].trim();
    const url        = /^https?:\/\//.test(rawUrl) ? rawUrl : `http://${rawUrl}`;
    const status     = (cells[1] || '').trim() || null;

    results.push({ forum_name, url, status });
  }
  return results;
}

/**
 * Fetch the deepdarkCTI forum list and cache it in dw_forum_list.
 * Skips if cache is less than FORUM_LIST_TTL_MS old.
 */
async function syncForumList(force = false) {
  if (!force) {
    const { ts } = stmts.forumLastFetch.get();
    if (ts && Date.now() - ts < FORUM_LIST_TTL_MS) {
      return { synced: stmts.forumCount.get().count, skipped: true };
    }
  }

  let text;
  try {
    const resp = await fetch(DEEPDARKCTI_FORUM_URL, {
      signal: AbortSignal.timeout(15000),
      headers: { 'User-Agent': 'FreeIntelHub/1.0 (CTI research)' },
    });
    if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
    text = await resp.text();
  } catch (err) {
    console.error('[darkweb] syncForumList fetch error:', err.message);
    return { synced: 0, error: err.message };
  }

  const forums = parseForumMarkdown(text);
  if (forums.length === 0) {
    console.warn('[darkweb] syncForumList: parsed 0 entries — format may have changed');
    return { synced: 0, error: 'Parsed 0 entries' };
  }

  const now = Date.now();
  const upsertMany = db.transaction(rows => {
    for (const row of rows) stmts.upsertForum.run({ ...row, fetched_at: now });
  });
  upsertMany(forums);

  console.log(`[darkweb] syncForumList: synced ${forums.length} forums`);
  return { synced: forums.length, skipped: false };
}

// ── Custom site config ────────────────────────────────────────────────────────

/**
 * Parse DW_MONITORED_SITES env var.
 * Format: "Name|http://xxx.onion|category" (comma-separated entries)
 */
function parseCustomSites() {
  const raw = process.env.DW_MONITORED_SITES || '';
  if (!raw.trim()) return [];
  return raw
    .split(',')
    .map(entry => {
      const parts = entry.trim().split('|');
      if (parts.length < 2) return null;
      const [name, url, category = 'custom'] = parts.map(p => p.trim());
      if (!url.includes('.onion')) return null;
      return { name, url, category };
    })
    .filter(Boolean);
}

// ── Tor connectivity check ────────────────────────────────────────────────────

/**
 * Check if Tor's SOCKS5 proxy is reachable by attempting a TCP connection.
 * Returns true if Tor is running, false otherwise.
 */
async function checkTor() {
  const { hostname, port } = new URL(TOR_PROXY);
  return new Promise((resolve) => {
    const sock = require('net').createConnection({ host: hostname, port: parseInt(port, 10) || 9050 });
    sock.setTimeout(3000);
    sock.on('connect', () => { sock.destroy(); resolve(true); });
    sock.on('error',   () => resolve(false));
    sock.on('timeout', () => { sock.destroy(); resolve(false); });
  });
}

// ── Site fetching ─────────────────────────────────────────────────────────────

/**
 * Fetch a URL — routes through Tor for .onion addresses, direct for clearnet.
 * socks5h:// means Tor resolves the hostname — no DNS leaks for .onion.
 */
async function fetchSite(url, timeoutMs = 30000) {
  const parsed  = new URL(url);
  const isOnion = parsed.hostname.endsWith('.onion');
  const agent   = isOnion ? new SocksProxyAgent(TOR_PROXY) : undefined;
  const mod     = parsed.protocol === 'https:' ? https : http;

  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => { req.destroy(); reject(new Error(`Timeout after ${timeoutMs}ms`)); }, timeoutMs);

    const req = mod.get({
      hostname:           parsed.hostname,
      port:               parsed.port || (parsed.protocol === 'https:' ? 443 : 80),
      path:               parsed.pathname + (parsed.search || ''),
      agent,
      // .onion HTTPS sites use self-signed certs — rejectUnauthorized must be false
      rejectUnauthorized: false,
      headers: {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; rv:109.0) Gecko/20100101 Firefox/115.0',
        'Accept':     'text/html,application/xhtml+xml,*/*;q=0.8',
      },
    }, (res) => {
      clearTimeout(timer);
      if (res.statusCode >= 400) {
        res.resume();
        return reject(new Error(`HTTP ${res.statusCode}`));
      }
      let body = '';
      res.on('data', chunk => { body += chunk; });
      res.on('end',  ()    => resolve(load(body)));
    });

    req.on('error', e => { clearTimeout(timer); reject(e); });
  });
}

/**
 * Extract a short text snippet from a cheerio document.
 * Tries common content selectors, falls back to first <p>, then body text.
 */
function extractSnippet($, maxLen = 300) {
  const selectors = [
    'article p', 'main p', '.content p', '.post p',
    'p', 'div.text', 'div.body', 'td',
  ];
  for (const sel of selectors) {
    const text = $(sel).first().text().replace(/\s+/g, ' ').trim();
    if (text.length > 20) return text.slice(0, maxLen);
  }
  return $('body').text().replace(/\s+/g, ' ').trim().slice(0, maxLen);
}

// ── Main scan ─────────────────────────────────────────────────────────────────

/**
 * Shared scan engine — iterates targets, fetches each, stores new hits.
 * Returns { found, errors }
 */
async function scanTargets(targets, label = 'scan') {
  if (targets.length === 0) {
    console.warn(`[darkweb] ${label}: no targets`);
    return { found: 0, errors: 0 };
  }

  let found = 0;
  let errors = 0;
  const now = Date.now();

  for (const target of targets) {
    try {
      const $ = await fetchSite(target.url);
      const title   = $('title').text().trim() || target.name;
      const snippet = extractSnippet($);

      // Deduplicate: skip if same url + title already stored
      if (stmts.existsHit.get({ onion_url: target.url, title })) continue;

      stmts.insertHit.run({
        site_name:       target.name,
        onion_url:       target.url,
        category:        target.category,
        title,
        content_snippet: snippet || null,
        discovered_at:   now,
        severity:        target.category === 'ransomware' ? 'high' : 'medium',
      });
      found++;
    } catch (err) {
      console.error(`[darkweb] ${label} error for ${target.url}:`, err.message);
      errors++;
    }
  }

  console.log(`[darkweb] ${label}: found=${found} errors=${errors} / ${targets.length} targets`);
  return { found, errors };
}

/**
 * Scan only forums from the dw_forum_list (ONLINE entries).
 * Clearnet forums are fetched directly; .onion forums go through Tor.
 */
async function scanForums() {
  const forums = stmts.forumList.all().filter(f => (f.status || '').toUpperCase() === 'ONLINE');
  const targets = forums.map(f => ({ name: f.forum_name, url: f.url, category: 'forum' }));
  return scanTargets(targets, 'scanForums');
}

/**
 * Scan all monitored sites:
 *   1. Cached ransomware gang list (dw_gang_list)
 *   2. ONLINE forums from dw_forum_list
 *   3. Custom sites from DW_MONITORED_SITES
 *
 * For each site: fetch → extract title + snippet → store if new.
 * Returns { found, errors }
 */
async function scanAll() {
  const gangs   = stmts.gangList.all();
  const forums  = stmts.forumList.all().filter(f => (f.status || '').toUpperCase() === 'ONLINE');
  const customs = parseCustomSites();

  const targets = [
    ...gangs.map(g  => ({ name: g.group_name, url: g.onion_url, category: 'ransomware' })),
    ...forums.map(f => ({ name: f.forum_name, url: f.url,       category: 'forum' })),
    ...customs.map(c => ({ name: c.name,      url: c.url,       category: c.category })),
  ];

  return scanTargets(targets, 'scanAll');
}

// ── DB reads ──────────────────────────────────────────────────────────────────

function getRecent({ page = 1, perPage = 20, category } = {}) {
  const offset = (page - 1) * perPage;
  if (category) {
    return stmts.recentByCat.all({ category, limit: perPage, offset });
  }
  return stmts.recentHits.all({ limit: perPage, offset });
}

function getCount(category) {
  if (category) return stmts.countByCat.get({ category }).count;
  return stmts.countAll.get().count;
}

function getGangList() {
  return stmts.gangList.all();
}

// ── Exports ───────────────────────────────────────────────────────────────────

function getForumList() {
  return stmts.forumList.all();
}

module.exports = { syncGangList, syncForumList, scanAll, scanForums, getRecent, getCount, getGangList, getForumList, checkTor };
