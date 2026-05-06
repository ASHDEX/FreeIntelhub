'use strict';

/**
 * YARA Rule Search Service
 *
 * Searches for actual YARA rules by querying the Neo23x0/signature-base
 * repository (one of the most comprehensive free YARA rule collections).
 *
 * Strategy:
 *   1. Fetch + cache the repo's file tree (24h TTL) — no auth required.
 *   2. Filter .yar files whose names contain the search term.
 *   3. Fetch raw content of up to 5 matching files in parallel.
 *   4. Parse individual rule blocks and extract meta (author, desc, ref, date).
 *
 * Source: https://github.com/Neo23x0/signature-base
 */

const TREE_URL    = 'https://api.github.com/repos/Neo23x0/signature-base/git/trees/master?recursive=0';
const RAW_BASE    = 'https://raw.githubusercontent.com/Neo23x0/signature-base/master/';
const CACHE_TTL   = 24 * 60 * 60 * 1000; // 24 hours
const MAX_FILES   = 5;
const MAX_RULES   = 20;

const HEADERS = { 'User-Agent': 'FreeIntelhub/1.0' };

let _treeCache = null;
let _treeCacheTs = 0;

async function getTree() {
  const now = Date.now();
  if (_treeCache && now - _treeCacheTs < CACHE_TTL) return _treeCache;
  try {
    const resp = await fetch(TREE_URL, {
      headers: HEADERS,
      signal: AbortSignal.timeout(15000),
    });
    if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
    const data = await resp.json();
    // Keep only .yar files, strip vendor/
    _treeCache = (data.tree || [])
      .filter(f => f.type === 'blob' && f.path.endsWith('.yar') && !f.path.startsWith('vendor/'))
      .map(f => f.path);
    _treeCacheTs = now;
  } catch (err) {
    console.error('[yara-search] tree fetch failed:', err.message);
    if (_treeCache) return _treeCache;
    return [];
  }
  return _treeCache;
}

/**
 * Parse individual YARA rule blocks from raw file text.
 * Returns an array of { ruleName, author, description, reference, date, content }.
 */
function parseRules(text, filePath) {
  const rules = [];
  // Split on rule/private rule boundaries
  const blocks = text.split(/(?=^(?:private\s+)?rule\s+\w+)/m);

  for (const block of blocks) {
    const trimmed = block.trim();
    if (!trimmed) continue;

    const nameMatch = trimmed.match(/^(?:private\s+)?rule\s+(\w+)/);
    if (!nameMatch) continue;

    const ruleName = nameMatch[1];

    // Extract meta fields
    const metaSection = trimmed.match(/meta\s*:([\s\S]*?)(?:strings\s*:|condition\s*:)/);
    const meta = metaSection ? metaSection[1] : '';

    const get = (key) => {
      const m = meta.match(new RegExp(key + '\\s*=\\s*"([^"]*)"', 'i'));
      return m ? m[1].trim() : '';
    };

    rules.push({
      ruleName,
      author:      get('author'),
      description: get('description'),
      reference:   get('reference'),
      date:        get('date'),
      sourceFile:  filePath.split('/').pop(),
      ruleContent: trimmed,
    });
  }

  return rules;
}

/**
 * Search for YARA rules matching the query.
 * Returns up to MAX_RULES rule objects with actual rule content.
 */
async function searchYaraRules(query, limit = MAX_RULES) {
  if (!query) return [];
  const q = query.toLowerCase().replace(/[^a-z0-9_\-]/g, '');
  if (!q) return [];

  const tree = await getTree();
  if (!tree.length) return [];

  // Score files by how closely their name matches the query
  const scored = tree
    .map(path => {
      const filename = path.split('/').pop().replace('.yar', '').toLowerCase();
      // Exact filename match gets highest score
      let score = 0;
      if (filename === q) score = 100;
      else if (filename.includes(q)) score = 50 + (q.length / filename.length) * 30;
      else if (q.split(/[-_]/).some(part => part.length > 2 && filename.includes(part))) score = 20;
      return { path, score };
    })
    .filter(x => x.score > 0)
    .sort((a, b) => b.score - a.score)
    .slice(0, MAX_FILES)
    .map(x => x.path);

  if (!scored.length) return [];

  // Fetch file contents in parallel
  const fetches = scored.map(path =>
    fetch(RAW_BASE + path, { headers: HEADERS, signal: AbortSignal.timeout(10000) })
      .then(r => r.ok ? r.text() : '')
      .then(text => text ? parseRules(text, path) : [])
      .catch(() => [])
  );

  const results = await Promise.all(fetches);
  const allRules = results.flat();

  // Further filter rules whose names/descriptions contain the query
  const filtered = allRules.filter(r => {
    const hay = (r.ruleName + ' ' + r.description).toLowerCase();
    return hay.includes(q) || q.split(/[-_]/).some(p => p.length > 2 && hay.includes(p));
  });

  return (filtered.length ? filtered : allRules).slice(0, limit);
}

module.exports = { searchYaraRules };
