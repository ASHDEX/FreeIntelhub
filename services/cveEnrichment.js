/**
 * CVE Enrichment Service
 *
 * Pulls two free public datasets daily:
 *   - FIRST.org EPSS  (Exploit Prediction Scoring System) — daily JSON dump
 *   - CISA KEV catalog (Known Exploited Vulnerabilities) — daily JSON dump
 *
 * Stores per-CVE rows in the cve_enrichment table. Used by the CVE views
 * to render an EPSS percentile badge and a "On CISA KEV" badge — these
 * transform CVE prioritisation from "high CVSS" to "actually exploited".
 *
 * Both endpoints are public, no auth needed. Designed to be safe on
 * shared hosting: streams JSON, parses progressively, batched UPSERTs.
 */

const https = require('https');
const db = require('../db');

const EPSS_URL = 'https://api.first.org/data/v1/epss?envelope=false&pretty=false&order=!epss';
const KEV_URL  = 'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json';

function fetchJson(url, timeoutMs = 30000) {
  return new Promise((resolve, reject) => {
    const req = https.get(url, { headers: { 'User-Agent': 'FreeIntelHub/1.0' } }, (res) => {
      if (res.statusCode !== 200) {
        res.resume();
        return reject(new Error(`HTTP ${res.statusCode} from ${url}`));
      }
      const chunks = [];
      res.on('data', (c) => chunks.push(c));
      res.on('end', () => {
        try { resolve(JSON.parse(Buffer.concat(chunks).toString('utf8'))); }
        catch (e) { reject(new Error('JSON parse failed: ' + e.message)); }
      });
    });
    req.setTimeout(timeoutMs, () => { req.destroy(new Error('timeout')); });
    req.on('error', reject);
  });
}

const upsertEpss = db.prepare(`
  INSERT INTO cve_enrichment (cve_id, epss, epss_percentile, epss_updated_at, last_synced_at)
  VALUES (?, ?, ?, ?, datetime('now'))
  ON CONFLICT(cve_id) DO UPDATE SET
    epss = excluded.epss,
    epss_percentile = excluded.epss_percentile,
    epss_updated_at = excluded.epss_updated_at,
    last_synced_at = datetime('now')
`);

const upsertKev = db.prepare(`
  INSERT INTO cve_enrichment (cve_id, on_kev, kev_added_at, kev_due_date, kev_known_ransomware, last_synced_at)
  VALUES (?, 1, ?, ?, ?, datetime('now'))
  ON CONFLICT(cve_id) DO UPDATE SET
    on_kev = 1,
    kev_added_at = excluded.kev_added_at,
    kev_due_date = excluded.kev_due_date,
    kev_known_ransomware = excluded.kev_known_ransomware,
    last_synced_at = datetime('now')
`);

const clearStaleKev = db.prepare(`
  UPDATE cve_enrichment SET on_kev = 0
  WHERE on_kev = 1 AND last_synced_at < datetime('now', '-2 days')
`);

async function syncEpss() {
  // EPSS exposes paginated JSON; we limit to top 30k by score (well over the
  // total CVE-of-interest set in this app — we never have that many). The
  // FIRST API caps at offset 30k anyway.
  const all = [];
  let offset = 0, fetched = 0;
  const PAGE = 5000;
  while (offset < 30000) {
    const url = `${EPSS_URL}&limit=${PAGE}&offset=${offset}`;
    let body;
    try { body = await fetchJson(url); }
    catch (e) { console.warn(`[EPSS] page ${offset} failed: ${e.message}`); break; }
    // FIRST.org returns a bare array when envelope=false, an object with .data otherwise.
    const items = Array.isArray(body) ? body : (Array.isArray(body.data) ? body.data : []);
    if (!items.length) break;
    all.push(...items);
    fetched += items.length;
    if (items.length < PAGE) break;
    offset += PAGE;
  }
  const tx = db.transaction((rows) => {
    for (const r of rows) {
      if (!r.cve) continue;
      upsertEpss.run(r.cve, parseFloat(r.epss) || 0, parseFloat(r.percentile) || 0, r.date || null);
    }
  });
  tx(all);
  console.log(`[EPSS] synced ${fetched} entries`);
  return fetched;
}

async function syncKev() {
  let body;
  try { body = await fetchJson(KEV_URL); }
  catch (e) { console.warn(`[KEV] fetch failed: ${e.message}`); return 0; }
  const items = Array.isArray(body.vulnerabilities) ? body.vulnerabilities : [];
  const tx = db.transaction((rows) => {
    for (const v of rows) {
      if (!v.cveID) continue;
      const ransom = (v.knownRansomwareCampaignUse || '').toLowerCase() === 'known' ? 1 : 0;
      upsertKev.run(v.cveID, v.dateAdded || null, v.dueDate || null, ransom);
    }
  });
  tx(items);
  // Clear stale entries that fell off the catalog
  clearStaleKev.run();
  console.log(`[KEV] synced ${items.length} entries`);
  return items.length;
}

async function syncAll() {
  try {
    const [e, k] = await Promise.allSettled([syncEpss(), syncKev()]);
    return {
      epss: e.status === 'fulfilled' ? e.value : `err: ${e.reason && e.reason.message}`,
      kev:  k.status === 'fulfilled' ? k.value : `err: ${k.reason && k.reason.message}`,
    };
  } catch (err) {
    console.warn('[CVE Enrichment] sync failed:', err.message);
    return { error: err.message };
  }
}

const getEnrichment = db.prepare(`SELECT * FROM cve_enrichment WHERE cve_id = ?`);

function getCveEnrichment(cveId) {
  if (!cveId) return null;
  return getEnrichment.get(cveId.toUpperCase()) || null;
}

module.exports = { syncAll, syncEpss, syncKev, getCveEnrichment };
