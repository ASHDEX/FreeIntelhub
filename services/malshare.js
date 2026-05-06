'use strict';

/**
 * MalShare Service
 *
 * Hash lookups and recent malware feed from MalShare (https://malshare.com).
 * Requires MALSHARE_API_KEY env var. All functions return structured objects
 * and never throw — failures return { skipped: true } or empty values.
 *
 * Rate limit: 2,000 requests/day on the free tier.
 */

const API_KEY = () => process.env.MALSHARE_API_KEY || '';
const BASE    = 'https://malshare.com/api.php';

// In-memory cache for getlist (1 hour TTL)
let _recentCache = null;
let _recentTs    = 0;
const CACHE_TTL_MS = 60 * 60 * 1000;

/**
 * Look up a file hash in MalShare.
 * Returns { found, sha256, md5, sha1, fileType, ssdeep, sources }
 * or { found: false, error? } or { skipped: true } if no API key.
 */
async function malshareHash(hash) {
  if (!API_KEY()) return { skipped: true };
  try {
    const url  = `${BASE}?api_key=${encodeURIComponent(API_KEY())}&action=details&hash=${encodeURIComponent(hash)}`;
    const resp = await fetch(url, { signal: AbortSignal.timeout(10000) });
    if (!resp.ok) return { found: false, error: `HTTP ${resp.status}` };
    const data = await resp.json();
    if (data && data.error) return { found: false };
    return {
      found:    true,
      sha256:   data.SHA256  || null,
      md5:      data.MD5     || null,
      sha1:     data.SHA1    || null,
      fileType: data.F_TYPE  || null,
      ssdeep:   data.SSDEEP  || null,
      sources:  Array.isArray(data.SOURCES) ? data.SOURCES : [],
    };
  } catch (e) {
    return { found: false, error: e.message };
  }
}

/**
 * Get the last 24h malware samples from MalShare (cached 1 hour).
 * Returns an array of { md5, sha1, sha256, type, source } objects,
 * or [] if no API key or on error.
 */
async function malshareRecent() {
  if (!API_KEY()) return [];
  const now = Date.now();
  if (_recentCache && (now - _recentTs) < CACHE_TTL_MS) return _recentCache;
  try {
    const url  = `${BASE}?api_key=${encodeURIComponent(API_KEY())}&action=getlist`;
    const resp = await fetch(url, { signal: AbortSignal.timeout(10000) });
    if (!resp.ok) return [];
    const data = await resp.json();
    if (!Array.isArray(data)) return [];
    _recentCache = data.map(s => ({
      md5:    s.md5    || null,
      sha1:   s.sha1   || null,
      sha256: s.sha256 || null,
      type:   s.type   || null,
      source: s.source || null,
    }));
    _recentTs = now;
    return _recentCache;
  } catch (_) {
    return [];
  }
}

module.exports = { malshareHash, malshareRecent };
