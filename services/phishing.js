'use strict';

const https = require('https');

/**
 * Phishing Lookup Service
 *
 * Fetches the deepdarkCTI phishing tools list from GitHub, caches in-memory
 * for 24 hours, and provides deep-link URL builders for services that support
 * pre-filling a query URL in their search interface.
 *
 * Source: https://github.com/fastfire/deepdarkCTI/blob/main/phishing.md
 */

const README_URL = 'https://raw.githubusercontent.com/fastfire/deepdarkCTI/main/phishing.md';
const CACHE_TTL_MS = 24 * 60 * 60 * 1000; // 24 hours

let _cache = null;
let _cacheTs = 0;

// ── Live feed caches ──────────────────────────────────────────────────────────
const FEED_TTL_MS = 6 * 60 * 60 * 1000; // 6 hours

const _feeds = {
  openphish: {
    url: 'https://openphish.com/feed.txt',
    // Full URLs, one per line — match on full URL or hostname
    urls: null, domains: null, ts: 0, size: 0,
  },
  phishdb: {
    url: 'https://raw.githubusercontent.com/mitchellkrogza/Phishing.Database/master/phishing-domains-ACTIVE.txt',
    // Domains only — match on hostname
    urls: null, domains: null, ts: 0, size: 0,
  },
  phisharmy: {
    url: 'https://phishing.army/download/phishing_army_blocklist.txt',
    // Domains/hosts, one per line — match on hostname
    urls: null, domains: null, ts: 0, size: 0,
  },
};

function parseFeedLines(text) {
  const urls = new Set();
  const domains = new Set();
  for (const raw of text.split('\n')) {
    const line = raw.trim();
    if (!line || line.startsWith('#')) continue;
    urls.add(line.toLowerCase());
    const host = extractHost(line).toLowerCase();
    if (host && host !== line.toLowerCase()) domains.add(host);
    else domains.add(line.toLowerCase()); // bare domain entry
  }
  return { urls, domains };
}

async function refreshFeed(key) {
  const feed = _feeds[key];
  const now = Date.now();
  if (feed.urls && now - feed.ts < FEED_TTL_MS) return;
  try {
    const resp = await fetch(feed.url, {
      headers: { 'User-Agent': 'FreeIntelhub/1.0' },
      signal: AbortSignal.timeout(30000),
    });
    if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
    const { urls, domains } = parseFeedLines(await resp.text());
    feed.urls = urls;
    feed.domains = domains;
    feed.ts = now;
    feed.size = urls.size + domains.size;
    console.log(`[phishing] feed ${key} loaded: ${urls.size} entries`);
  } catch (err) {
    console.error(`[phishing] feed ${key} fetch failed:`, err.message);
  }
}

async function checkFeed(key, url) {
  await refreshFeed(key);
  const feed = _feeds[key];
  if (!feed.urls) return { found: false, error: 'Feed unavailable' };
  const host = extractHost(url).toLowerCase();
  const normalUrl = url.toLowerCase().replace(/\/+$/, '');
  const found = feed.urls.has(normalUrl) || feed.domains.has(host);
  return { found, size: feed.size };
}

// Warm all feed caches in the background 10s after module load
setTimeout(() => {
  Object.keys(_feeds).forEach(key => refreshFeed(key).catch(() => {}));
}, 10000);

/**
 * Safely extract hostname from a URL string.
 * Falls back to the raw string for bare domains without a scheme.
 */
function extractHost(url) {
  try {
    const u = url.includes('://') ? url : `https://${url}`;
    return new URL(u).hostname;
  } catch (_) {
    return url;
  }
}

/**
 * Parse the phishing.md markdown table into an array of service objects.
 * Table format: | [Name](url) | STATUS | description |
 */
function parseMd(text) {
  const entries = [];
  const lines = text.split('\n');
  for (const line of lines) {
    // Skip header and separator rows
    if (!line.startsWith('|')) continue;
    if (/Name|-----/.test(line)) continue;

    // Match: | [Name](URL) | STATUS | desc |
    const match = line.match(/\|\s*\[([^\]]+)\]\(([^)]+)\)\s*\|\s*(\w+)\s*\|([^|]*)\|?/);
    if (!match) continue;

    entries.push({
      name: match[1].trim(),
      url: match[2].trim(),
      status: match[3].trim().toUpperCase(),
      description: match[4].trim(),
    });
  }
  return entries;
}

async function fetchAndParse() {
  const resp = await fetch(README_URL, {
    headers: { 'User-Agent': 'FreeIntelhub/1.0' },
    signal: AbortSignal.timeout(15000),
  });
  if (!resp.ok) throw new Error(`HTTP ${resp.status} fetching phishing sources`);
  return parseMd(await resp.text());
}

/**
 * Get cached sources, refreshing if stale.
 */
async function getSources() {
  const now = Date.now();
  if (_cache && now - _cacheTs < CACHE_TTL_MS) return _cache;
  try {
    _cache = await fetchAndParse();
    _cacheTs = now;
  } catch (err) {
    console.error('[phishing] fetch failed:', err.message);
    if (_cache) return _cache;
    return [];
  }
  return _cache;
}

/**
 * Deep-link URL builders for services that support pre-filling a URL/domain
 * in their search interface via query parameters.
 */
const DEEP_LINK_PATTERNS = {
  'urlscan.io':           (u) => `https://urlscan.io/search/#page.url:${encodeURIComponent(u)}`,
  'PhishStats':           (u) => `https://phishstats.info/?search=${encodeURIComponent(extractHost(u))}`,
  'EasyDmark':            (u) => `https://easydmarc.com/tools/phishing-url?url=${encodeURIComponent(u)}`,
  'CheckPhish':           (u) => `https://checkphish.ai/?url=${encodeURIComponent(u)}`,
  'PhishHunt':            (u) => `https://phishunt.io/?url=${encodeURIComponent(u)}`,
  'StalkPhish.io':        (u) => `https://www.stalkphish.io/stalk/${encodeURIComponent(extractHost(u))}/`,
  'urlDNA.io':            (u) => `https://urldna.io/scan/${encodeURIComponent(u)}`,
  'ThreatCOp':            (u) => `https://threatcop.com/phishing-url-checker?url=${encodeURIComponent(u)}`,
  'PhishingCheck':        (u) => `https://phishcheck.me/?url=${encodeURIComponent(u)}`,
  'PhishingInitiative':   (u) => `https://phishing-initiative.fr/contrib/?url=${encodeURIComponent(u)}`,
};

/**
 * Query urlscan.io search API for scans matching the given URL/domain.
 * No API key required. Falls back to domain search if URL search returns 0 results.
 * Returns { found, malicious, records: [{ url, date, malicious, score, reportUrl }], error? }
 */
async function checkUrlscan(url) {
  const host = extractHost(url);
  async function search(q) {
    const resp = await fetch(
      `https://urlscan.io/api/v1/search/?q=${encodeURIComponent(q)}&size=10`,
      { headers: { 'User-Agent': 'FreeIntelhub/1.0' }, signal: AbortSignal.timeout(10000) }
    );
    if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
    return resp.json();
  }
  try {
    let data = await search(`page.url:"${url}"`);
    if (!data.results || data.results.length === 0) {
      data = await search(`page.domain:${host}`);
    }
    const results = (data.results || []).slice(0, 10);
    const records = results.map(r => ({
      url: r.page && r.page.url ? r.page.url : (r.task && r.task.url ? r.task.url : ''),
      date: r.task && r.task.time ? r.task.time.slice(0, 10) : '',
      malicious: !!(r.verdicts && r.verdicts.overall && r.verdicts.overall.malicious),
      score: r.verdicts && r.verdicts.overall ? (r.verdicts.overall.score || 0) : 0,
      reportUrl: r._id ? `https://urlscan.io/result/${r._id}/` : '',
    }));
    const malicious = records.filter(r => r.malicious).length;
    return { found: records.length, malicious, records };
  } catch (err) {
    return { found: 0, malicious: 0, records: [], error: err.message };
  }
}

/**
 * Query PhishStats API for phishing records matching the given URL/domain.
 * No API key required.
 * Returns { found, records: [{ url, date, ip, country }], error? }
 */
async function checkPhishStats(url) {
  const host = extractHost(url);
  try {
    const resp = await fetch(
      `https://phishstats.info:2096/api/phishing?_where=(url,like,~${encodeURIComponent(host)}~)&_size=10`,
      { headers: { 'User-Agent': 'FreeIntelhub/1.0' }, signal: AbortSignal.timeout(10000) }
    );
    if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
    const data = await resp.json();
    const records = (Array.isArray(data) ? data : []).slice(0, 10).map(r => ({
      url: r.url || '',
      date: r.date ? r.date.slice(0, 10) : '',
      ip: r.ip || '',
      country: r.countrycode || '',
    }));
    return { found: records.length, records };
  } catch (err) {
    return { found: 0, records: [], error: err.message };
  }
}

/**
 * Query CheckPhish (Bolster) API for a URL verdict.
 * Requires CHECKPHISH_API_KEY env var. The API is async: submit → poll until DONE.
 * Returns { disposition, brand, malicious, url, error? } or { skipped: true } if no key.
 */
async function checkCheckPhish(url) {
  const apiKey = process.env.CHECKPHISH_API_KEY;
  if (!apiKey) return { skipped: true };

  try {
    // Submit scan
    const submitResp = await fetch('https://developers.checkphish.ai/api/neo/scan', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'User-Agent': 'FreeIntelhub/1.0' },
      body: JSON.stringify({ apiKey, urlInfo: { url } }),
      signal: AbortSignal.timeout(10000),
    });
    if (!submitResp.ok) throw new Error(`Submit HTTP ${submitResp.status}`);
    const submitted = await submitResp.json();
    const jobID = submitted.jobID;
    if (!jobID) throw new Error('No jobID in response');

    // Poll for result (initial 2s delay, then every 1.5s, up to 10 attempts)
    await new Promise(r => setTimeout(r, 2000));
    for (let i = 0; i < 10; i++) {
      const statusResp = await fetch('https://developers.checkphish.ai/api/neo/scan/status', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'User-Agent': 'FreeIntelhub/1.0' },
        body: JSON.stringify({ apiKey, jobID, insights: true }),
        signal: AbortSignal.timeout(10000),
      });
      if (!statusResp.ok) {
        await new Promise(r => setTimeout(r, 1500));
        continue;
      }
      const data = await statusResp.json();
      if (data.status === 'DONE') {
        const disposition = (data.disposition || 'unknown').toLowerCase();
        return {
          disposition,
          brand: data.brand || '',
          malicious: disposition !== 'clean' && disposition !== 'unknown',
          url: data.url || url,
        };
      }
      await new Promise(r => setTimeout(r, 1500));
    }
    return { disposition: 'unknown', malicious: false, error: 'Scan timed out' };
  } catch (err) {
    return { disposition: 'unknown', malicious: false, error: err.message };
  }
}

/**
 * Query PhishingInitiative API for a URL verdict.
 * Uses https module directly (rejectUnauthorized:false) because their cert has issues.
 * Requires PHISHING_INITIATIVE_KEY env var.
 * Returns { tag, phishingScore, googleSafeBrowsing, error? } or { skipped: true } if no key.
 */
function checkPhishingInitiative(url) {
  const apiKey = process.env.PHISHING_INITIATIVE_KEY;
  if (!apiKey) return Promise.resolve({ skipped: true });

  return new Promise((resolve) => {
    const body = JSON.stringify({ url });
    const req = https.request({
      hostname: 'phishing-initiative.fr',
      path: '/api/v1/url/lookup/',
      method: 'POST',
      rejectUnauthorized: false,
      headers: {
        'Authorization': `Token ${apiKey}`,
        'Content-Type': 'application/json',
        'Content-Length': Buffer.byteLength(body),
        'User-Agent': 'FreeIntelhub/1.0',
      },
    }, (res) => {
      let raw = '';
      res.on('data', chunk => { raw += chunk; });
      res.on('end', () => {
        try {
          const data = JSON.parse(raw);
          const tag = (data.tag || 'unknown').toLowerCase();
          resolve({
            tag,
            phishingScore: data.phishing_score != null ? data.phishing_score : null,
            googleSafeBrowsing: data.google_safebrowsing || false,
            malicious: tag === 'phishing',
          });
        } catch (_) {
          resolve({ tag: 'unknown', malicious: false, error: `Parse error (status ${res.statusCode})` });
        }
      });
    });
    req.setTimeout(10000, () => { req.destroy(); resolve({ tag: 'unknown', malicious: false, error: 'Request timed out' }); });
    req.on('error', (err) => resolve({ tag: 'unknown', malicious: false, error: err.message }));
    req.write(body);
    req.end();
  });
}

/** Check OpenPhish live feed (full URL list, ~6hr cache). */
async function checkOpenPhish(url) { return checkFeed('openphish', url); }

/** Check Phishing.Database active domains list (~6hr cache). */
async function checkPhishingDatabase(url) { return checkFeed('phishdb', url); }

/** Check PhishingArmy blocklist (~6hr cache). */
async function checkPhishingArmy(url) { return checkFeed('phisharmy', url); }

module.exports = {
  getSources, DEEP_LINK_PATTERNS,
  checkUrlscan, checkPhishStats, checkCheckPhish, checkPhishingInitiative,
  checkOpenPhish, checkPhishingDatabase, checkPhishingArmy,
};
