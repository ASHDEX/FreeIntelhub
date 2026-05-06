'use strict';

/**
 * abuse.ch Integration Service
 *
 * Covers:
 *   - ThreatFox    (threatfox-api.abuse.ch) — IOC search for IPs, domains, hashes
 *   - MalwareBazaar (mb-api.abuse.ch)        — hash info + YARA rule search
 *   - URLhaus      (urlhaus-api.abuse.ch)    — malicious URL / host lookup
 *   - SSLBL        (sslbl.abuse.ch)          — SSL certificate blacklist (CSV, no key)
 *
 * All API endpoints now require Auth-Key header (abuse.ch unified auth, 2024+).
 * SSLBL CSV download does not require authentication.
 */

const db = require('../db');

const API_KEY = () => process.env.ABUSECH_API_KEY || '';

// ── HTTP helpers ──────────────────────────────────────────────────────────────

function authHeaders(extra = {}) {
  const key = API_KEY();
  return {
    'User-Agent': 'FreeIntelhub/1.0',
    ...(key ? { 'Auth-Key': key } : {}),
    ...extra,
  };
}

async function postJson(url, body) {
  const resp = await fetch(url, {
    method: 'POST',
    headers: authHeaders({ 'Content-Type': 'application/json' }),
    body: JSON.stringify(body),
    signal: AbortSignal.timeout(15000),
  });
  if (!resp.ok) throw new Error(`HTTP ${resp.status} from ${url}`);
  return resp.json();
}

// MalwareBazaar requires form-encoded POST (not JSON)
async function postForm(url, body) {
  const resp = await fetch(url, {
    method: 'POST',
    headers: authHeaders({ 'Content-Type': 'application/x-www-form-urlencoded' }),
    body: new URLSearchParams(body).toString(),
    signal: AbortSignal.timeout(15000),
  });
  if (!resp.ok) throw new Error(`HTTP ${resp.status} from ${url}`);
  return resp.json();
}

// ── ThreatFox ─────────────────────────────────────────────────────────────────

/**
 * Search ThreatFox for IOCs matching an IP, domain, URL, or hash.
 * Returns array of IOC objects (may be empty).
 */
async function threatFoxLookup(term) {
  if (!API_KEY()) return [];
  try {
    const data = await postJson('https://threatfox-api.abuse.ch/api/v1/', {
      query: 'search_ioc',
      search_term: term,
    });
    if (data.query_status !== 'ok' || !Array.isArray(data.data)) return [];
    return data.data.map(ioc => ({
      id: ioc.id,
      ioc: ioc.ioc,
      ioc_type: ioc.ioc_type,
      threat_type: ioc.threat_type,
      malware: ioc.malware,
      malware_printable: ioc.malware_printable,
      confidence_level: ioc.confidence_level,
      first_seen: ioc.first_seen,
      last_seen: ioc.last_seen,
      tags: Array.isArray(ioc.tags) ? ioc.tags : [],
      reporter: ioc.reporter,
      reference: ioc.reference,
    }));
  } catch (_) {
    return [];
  }
}

// ── MalwareBazaar ─────────────────────────────────────────────────────────────

/**
 * Look up a file hash (MD5/SHA1/SHA256) in MalwareBazaar.
 * Returns enriched object or null if not found.
 */
async function malwareBazaarHash(hash) {
  if (!API_KEY()) return null;
  try {
    const data = await postForm('https://mb-api.abuse.ch/api/v1/', {
      query: 'get_info',
      hash,
    });
    if (data.query_status !== 'ok' || !data.data || !data.data.length) return null;
    const s = data.data[0];
    return {
      sha256: s.sha256_hash,
      md5: s.md5_hash,
      sha1: s.sha1_hash,
      file_name: s.file_name,
      file_type: s.file_type_mime,
      file_size: s.file_size,
      signature: s.signature,           // malware family
      tags: Array.isArray(s.tags) ? s.tags : [],
      yara_rules: Array.isArray(s.yara_rules)
        ? s.yara_rules.map(r => ({ name: r.rule_name, author: r.rule_author, description: r.rule_description }))
        : [],
      first_seen: s.first_seen,
      last_seen: s.last_seen,
      imphash: s.imphash,
      ssdeep: s.ssdeep,
      delivery_method: s.delivery_method,
      origin_country: s.origin_country,
      intelligence: s.intelligence || {},
    };
  } catch (_) {
    return null;
  }
}

/**
 * Search YARAify for YARA rules matching a keyword/signature.
 * Returns array of { ruleName, ruleContent, author, description, tlp, dateAdded, tags }
 * ruleContent is the actual YARA rule text.
 */
async function yaraifySearch(query, limit = 20) {
  if (!API_KEY() || !query) return [];
  try {
    const data = await postJson('https://yaraify-api.abuse.ch/api/v1/', {
      query: 'search_yara',
      search_term: query,
    });
    if (data.query_status !== 'ok' || !Array.isArray(data.data)) return [];
    return data.data.slice(0, limit).map(r => ({
      ruleName:    r.rule_name    || '',
      ruleContent: r.rule_content || '',
      author:      r.author       || '',
      description: r.description  || '',
      tlp:         r.tlp          || '',
      dateAdded:   r.date_added   ? r.date_added.slice(0, 10) : '',
      tags:        Array.isArray(r.tags) ? r.tags : [],
    }));
  } catch (_) {
    return [];
  }
}

/**
 * Search MalwareBazaar by tag or malware name for YARA rules.
 * Returns array of sample objects each containing YARA rule data.
 */
async function malwareBazaarTag(tag, limit = 20) {
  if (!API_KEY()) return [];
  try {
    const data = await postForm('https://mb-api.abuse.ch/api/v1/', {
      query: 'get_taginfo',
      tag,
      limit,
    });
    if (data.query_status !== 'ok' || !Array.isArray(data.data)) return [];
    return data.data.map(s => ({
      sha256: s.sha256_hash,
      file_name: s.file_name,
      file_type: s.file_type_mime,
      file_size: s.file_size,
      signature: s.signature,
      tags: Array.isArray(s.tags) ? s.tags : [],
      yara_rules: Array.isArray(s.yara_rules)
        ? s.yara_rules.map(r => ({ name: r.rule_name, author: r.rule_author, description: r.rule_description }))
        : [],
      first_seen: s.first_seen,
    }));
  } catch (_) {
    return [];
  }
}

// ── URLhaus ───────────────────────────────────────────────────────────────────

/**
 * Look up a host (IP or domain) in URLhaus.
 * No API key required.
 */
async function urlhausHost(host) {
  try {
    const data = await postForm('https://urlhaus-api.abuse.ch/v1/host/', { host });
    if (!data || data.query_status === 'no_results' || data.query_status === 'no_result') return null;
    return {
      query_status: data.query_status,
      urlhaus_reference: data.urlhaus_reference,
      urls_count: data.urls_count || 0,
      blacklists: data.blacklists || {},
      urls: Array.isArray(data.urls)
        ? data.urls.slice(0, 10).map(u => ({
            url: u.url,
            url_status: u.url_status,
            date_added: u.date_added,
            threat: u.threat,
            tags: Array.isArray(u.tags) ? u.tags : [],
            reporter: u.reporter,
          }))
        : [],
    };
  } catch (_) {
    return null;
  }
}

// ── SSLBL ─────────────────────────────────────────────────────────────────────

const sslStmts = {
  upsert: db.prepare(`
    INSERT OR REPLACE INTO ssl_blacklist (sha1, listing_date, reason, synced_at)
    VALUES (?, ?, ?, datetime('now'))
  `),
  recent: db.prepare(`SELECT sha1, listing_date, reason FROM ssl_blacklist ORDER BY listing_date DESC LIMIT ?`),
  search: db.prepare(`SELECT sha1, listing_date, reason FROM ssl_blacklist WHERE sha1 LIKE ? OR reason LIKE ? ORDER BY listing_date DESC LIMIT 200`),
  count:  db.prepare(`SELECT COUNT(*) as c FROM ssl_blacklist`),
  log:    db.prepare(`INSERT INTO ssl_sync_log (count) VALUES (?)`),
  lastLog: db.prepare(`SELECT * FROM ssl_sync_log ORDER BY id DESC LIMIT 1`),
};

/**
 * Fetch the SSLBL CSV blacklist and store in SQLite.
 * CSV format (lines not starting with #): sha1fingerprint,listingdate,reason
 */
async function syncSslBlacklist() {
  const resp = await fetch('https://sslbl.abuse.ch/blacklist/sslblacklist.csv', {
    headers: { 'User-Agent': 'FreeIntelhub/1.0' },
    signal: AbortSignal.timeout(30000),
  });
  if (!resp.ok) throw new Error(`SSLBL returned HTTP ${resp.status}`);
  const text = await resp.text();

  const lines = text.split('\n').filter(l => l.trim() && !l.startsWith('#'));
  let count = 0;

  const insertMany = db.transaction(() => {
    for (const line of lines) {
      const parts = line.split(',');
      if (parts.length < 2) continue;
      // SSLBL CSV format: listingdate,sha1,reason
      const listingDate = parts[0].trim();
      const sha1 = parts[1].trim();
      const reason = parts.slice(2).join(',').trim() || '';
      if (!sha1) continue;
      sslStmts.upsert.run(sha1, listingDate, reason);
      count++;
    }
  });
  insertMany();

  sslStmts.log.run(count);
  return count;
}

function getRecentSslBlacklist(limit = 500) {
  return sslStmts.recent.all(limit);
}

function searchSslBlacklist(q) {
  const pat = `%${q}%`;
  return sslStmts.search.all(pat, pat);
}

function getSslBlacklistCount() {
  return sslStmts.count.get().c;
}

function getLastSslSync() {
  return sslStmts.lastLog.get() || null;
}

module.exports = {
  threatFoxLookup,
  malwareBazaarHash,
  malwareBazaarTag,
  yaraifySearch,
  urlhausHost,
  syncSslBlacklist,
  getRecentSslBlacklist,
  searchSslBlacklist,
  getSslBlacklistCount,
  getLastSslSync,
};
