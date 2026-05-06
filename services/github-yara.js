'use strict';

/**
 * InQuest/awesome-yara Integration
 *
 * Fetches the curated awesome-yara README from GitHub, parses rule repository
 * entries, caches them in-memory (refreshed every 24 hours), and provides
 * keyword search across repo names and descriptions.
 *
 * Source: https://github.com/InQuest/awesome-yara
 */

const README_URL = 'https://raw.githubusercontent.com/InQuest/awesome-yara/master/README.md';
const CACHE_TTL_MS = 24 * 60 * 60 * 1000; // 24 hours

let _cache = null;       // parsed entries []
let _cacheTs = 0;        // timestamp of last successful fetch

/**
 * Fetch and parse the awesome-yara README.
 * Returns an array of { name, url, description } objects from the Rules section.
 */
async function fetchAndParse() {
  const resp = await fetch(README_URL, {
    headers: { 'User-Agent': 'FreeIntelhub/1.0' },
    signal: AbortSignal.timeout(20000),
  });
  if (!resp.ok) throw new Error(`HTTP ${resp.status} fetching awesome-yara README`);
  const text = await resp.text();
  return parseReadme(text);
}

/**
 * Parse rule entries from the README.
 * Extracts all sections, focusing on entries formatted as:
 *   * [Name](URL)
 *       - Description text
 */
function parseReadme(text) {
  const entries = [];

  // Split into lines for sequential processing
  const lines = text.split('\n');
  let inRulesSection = false;

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];

    // Track section headers (## Rules, ## Tools, etc.)
    if (/^##\s+/.test(line)) {
      // Include all sections that list rule repos (Rules, and 100 Days of YARA)
      const heading = line.replace(/^##\s+/, '').toLowerCase();
      inRulesSection = heading.includes('rule') || heading.includes('100 days');
      continue;
    }

    if (!inRulesSection) continue;

    // Match list items: * [Name](URL) or * [Name](URL) :emoji: - desc inline
    const listMatch = line.match(/^\*\s+\[([^\]]+)\]\(([^)]+)\)(.*)/);
    if (!listMatch) continue;

    const name = listMatch[1].trim();
    const url = listMatch[2].trim();
    // Inline description after the link (strip emojis / badge markers)
    let desc = listMatch[3].replace(/:[\w_]+:/g, '').replace(/^[\s\-–—]+/, '').trim();

    // If description is missing or very short, check the next non-empty line
    if (desc.length < 10) {
      for (let j = i + 1; j < Math.min(i + 4, lines.length); j++) {
        const next = lines[j].trim();
        if (!next) continue;
        // Continuation lines start with - or are indented
        if (/^[-–]/.test(next) || /^\s{4,}/.test(lines[j])) {
          desc = next.replace(/^[-–\s]+/, '').trim();
        }
        break;
      }
    }

    if (name && url) {
      entries.push({ name, url, description: desc });
    }
  }

  return entries;
}

/**
 * Get cached entries, refreshing if stale.
 */
async function getEntries() {
  const now = Date.now();
  if (_cache && now - _cacheTs < CACHE_TTL_MS) return _cache;
  try {
    _cache = await fetchAndParse();
    _cacheTs = now;
  } catch (err) {
    console.error('[github-yara] fetch failed:', err.message);
    // Return stale cache if available, else empty
    if (_cache) return _cache;
    return [];
  }
  return _cache;
}

/**
 * Search awesome-yara entries by keyword.
 * Matches against repo name and description (case-insensitive).
 * Returns up to `limit` results sorted by match quality.
 */
async function searchAwesomeYara(query, limit = 10) {
  if (!query) return [];
  const entries = await getEntries();
  const terms = query.toLowerCase().split(/\s+/).filter(Boolean);

  const scored = entries
    .map(e => {
      const haystack = (e.name + ' ' + e.description).toLowerCase();
      // Score: 2 points for name match, 1 for description match, per term
      let score = 0;
      for (const t of terms) {
        if (e.name.toLowerCase().includes(t)) score += 2;
        else if (haystack.includes(t)) score += 1;
      }
      return { entry: e, score };
    })
    .filter(x => x.score > 0)
    .sort((a, b) => b.score - a.score)
    .slice(0, limit)
    .map(x => x.entry);

  return scored;
}

/**
 * Force-refresh the cache (useful for admin endpoints).
 */
async function refreshCache() {
  _cache = await fetchAndParse();
  _cacheTs = Date.now();
  return _cache.length;
}

module.exports = { searchAwesomeYara, refreshCache };
