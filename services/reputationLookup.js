/**
 * Reputation Lookup
 *
 * Thin wrapper around existing AbuseIPDB / VirusTotal / RDAP lookups in
 * services/threatIntel.js. Auto-detects IOC type and dispatches lazily.
 *
 * Designed for on-demand UI calls only — never bulk. Both providers have
 * tight free-tier quotas (AbuseIPDB 1k/day, VT 4/min). Caching here is
 * an in-memory LRU with 1-hour TTL to absorb repeat clicks without burning
 * the quota.
 */

const { lookupIP, lookupDomain, lookupHash } = require('./threatIntel');

const TTL_MS = 60 * 60 * 1000; // 1h
const MAX_ENTRIES = 500;
const cache = new Map(); // key -> { ts, value }

function cacheGet(key) {
  const hit = cache.get(key);
  if (!hit) return null;
  if (Date.now() - hit.ts > TTL_MS) { cache.delete(key); return null; }
  // Promote to MRU
  cache.delete(key); cache.set(key, hit);
  return hit.value;
}
function cacheSet(key, value) {
  if (cache.size >= MAX_ENTRIES) {
    // Drop the oldest
    const first = cache.keys().next().value;
    if (first) cache.delete(first);
  }
  cache.set(key, { ts: Date.now(), value });
}

const RE_IPV4   = /^(?:\d{1,3}\.){3}\d{1,3}$/;
const RE_HASH   = /^[a-f0-9]{32}$|^[a-f0-9]{40}$|^[a-f0-9]{64}$/i;
const RE_DOMAIN = /^(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+[a-z]{2,}$/i;

function classify(ioc) {
  if (!ioc || typeof ioc !== 'string') return null;
  const v = ioc.trim();
  if (RE_IPV4.test(v))   return 'ipv4';
  if (RE_HASH.test(v))   return 'hash';
  if (RE_DOMAIN.test(v)) return 'domain';
  return null;
}

/**
 * Lookup reputation for any IOC. Returns:
 *   { ok: true, type, data, source, cached?: true }
 *   { ok: false, error: 'unsupported' | 'not-configured' | 'lookup-failed' }
 */
async function lookupReputation(ioc) {
  const type = classify(ioc);
  if (!type) return { ok: false, error: 'unsupported', detail: 'IOC type not recognized (need IPv4 / domain / md5/sha1/sha256)' };

  const key = `${type}:${ioc.toLowerCase()}`;
  const cached = cacheGet(key);
  if (cached) return { ...cached, cached: true };

  try {
    let data, source;
    if (type === 'ipv4') {
      source = 'AbuseIPDB';
      if (!process.env.ABUSEIPDB_KEY) return { ok: false, error: 'not-configured', source };
      data = await lookupIP(ioc);
    } else if (type === 'hash') {
      source = 'VirusTotal';
      if (!process.env.VIRUSTOTAL_API_KEY) return { ok: false, error: 'not-configured', source };
      data = await lookupHash(ioc);
    } else if (type === 'domain') {
      source = 'RDAP';
      data = await lookupDomain(ioc);
    }
    const result = { ok: true, type, data, source };
    cacheSet(key, result);
    return result;
  } catch (err) {
    return { ok: false, error: 'lookup-failed', detail: err.message };
  }
}

module.exports = { lookupReputation, classify };
