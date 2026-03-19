'use strict';

/**
 * Malpedia enrichment service
 * Bulk-imports malware family and threat actor data from Malpedia's
 * public API (no API token required) and matches it against existing
 * entities in the local SQLite database.
 *
 * API base: https://malpedia.caad.fkie.fraunhofer.de/api/
 * Two HTTP calls total: /get/families and /get/actors
 */

const db = require('../db');

const MALPEDIA_BASE = 'https://malpedia.caad.fkie.fraunhofer.de/api';

// ── Normalisation helper ──────────────────────────────────────────────────────

function norm(s) {
  return String(s || '').toLowerCase().replace(/[^a-z0-9]/g, '');
}

// Build a set of normalised tokens for fast lookup
function tokenSet(names) {
  return new Set(names.map(norm).filter(Boolean));
}

// ── Name-matching ─────────────────────────────────────────────────────────────

/**
 * Returns true if any of the entity's names/aliases match any of the
 * Malpedia entry's names/alt_names (case-insensitive, symbols stripped).
 */
function entityMatchesMalpedia(entityName, entityAliases, malpediaNames) {
  const targets = tokenSet(malpediaNames);
  const candidates = tokenSet([entityName, ...entityAliases]);
  for (const c of candidates) {
    if (targets.has(c)) return true;
  }
  return false;
}

// ── HTTP helper ───────────────────────────────────────────────────────────────

async function fetchJson(url) {
  const resp = await fetch(url, {
    headers: { 'Accept': 'application/json', 'User-Agent': 'FreeIntelhub/1.0' },
    signal: AbortSignal.timeout(30000),
  });
  if (!resp.ok) throw new Error(`Malpedia API returned HTTP ${resp.status} for ${url}`);
  return resp.json();
}

// ── DB prepared statements ────────────────────────────────────────────────────

const stmts = {
  allSoftware: db.prepare('SELECT id, name, aliases, description, first_seen FROM malware_software'),
  allGroups:   db.prepare('SELECT id, name, aliases, description, country, first_seen FROM threat_groups'),

  updateSoftware: db.prepare(`
    UPDATE malware_software SET
      malpedia_slug = ?,
      malpedia_uuid = ?,
      malpedia_refs = ?,
      malpedia_attribution = ?,
      aliases = ?,
      description = CASE WHEN (description IS NULL OR description = '') THEN ? ELSE description END
    WHERE id = ?
  `),

  updateGroup: db.prepare(`
    UPDATE threat_groups SET
      malpedia_slug = ?,
      malpedia_uuid = ?,
      malpedia_refs = ?,
      aliases = ?,
      description = CASE WHEN (description IS NULL OR description = '') THEN ? ELSE description END,
      country = CASE WHEN (country IS NULL OR country = '') THEN ? ELSE country END,
      first_seen = CASE WHEN (first_seen IS NULL OR first_seen = '') THEN ? ELSE first_seen END
    WHERE id = ?
  `),

  logSync: db.prepare(`
    INSERT INTO malpedia_sync_log (families_fetched, actors_fetched, sw_matched, tg_matched)
    VALUES (?, ?, ?, ?)
  `),

  lastSync: db.prepare('SELECT * FROM malpedia_sync_log ORDER BY id DESC LIMIT 1'),
};

// ── Merge alias arrays ────────────────────────────────────────────────────────

function mergeAliases(existingJson, newNames) {
  const existing = (() => {
    try { return JSON.parse(existingJson || '[]'); } catch (_) { return []; }
  })();
  const merged = new Set([...existing, ...newNames].map(s => s.trim()).filter(Boolean));
  return JSON.stringify([...merged]);
}

// ── Main sync function ────────────────────────────────────────────────────────

async function syncMalpedia() {
  console.log('[Malpedia] Starting sync…');

  // 1. Fetch both datasets in parallel
  const [familiesDict, actorsDict] = await Promise.all([
    fetchJson(`${MALPEDIA_BASE}/get/families`),
    fetchJson(`${MALPEDIA_BASE}/get/actors`),
  ]);

  const familiesFetched = Object.keys(familiesDict).length;
  const actorsFetched   = Object.keys(actorsDict).length;
  console.log(`[Malpedia] Fetched ${familiesFetched} families, ${actorsFetched} actors`);

  // 2. Load all local entities
  const softwareRows = stmts.allSoftware.all();
  const groupRows    = stmts.allGroups.all();

  // 3. Build a lookup: slug → family for quick iteration
  let swMatched = 0;
  let tgMatched = 0;

  // ── Match malware families ────────────────────────────────────────────────
  const syncSoftware = db.transaction(() => {
    for (const [slug, fam] of Object.entries(familiesDict)) {
      const commonName  = fam.common_name || '';
      const altNames    = Array.isArray(fam.alt_names) ? fam.alt_names : [];
      const description = fam.description || '';
      const attribution = Array.isArray(fam.attribution) ? fam.attribution : [];
      const urls        = Array.isArray(fam.urls) ? fam.urls : [];
      const uuid        = fam.uuid || '';

      // Also try the bare name from slug (e.g. "win.lockbit" → "lockbit")
      const slugName = slug.includes('.') ? slug.split('.').slice(1).join('.') : slug;
      const malpediaNames = [commonName, slugName, ...altNames].filter(Boolean);

      for (const row of softwareRows) {
        const rowAliases = (() => {
          try { return JSON.parse(row.aliases || '[]'); } catch (_) { return []; }
        })();

        if (entityMatchesMalpedia(row.name, rowAliases, malpediaNames)) {
          stmts.updateSoftware.run(
            slug,
            uuid,
            JSON.stringify(urls.slice(0, 20)),      // refs: up to 20 URLs
            JSON.stringify(attribution),             // malpedia_attribution
            mergeAliases(row.aliases, altNames),     // merged aliases
            description,                             // fill desc if empty
            row.id,
          );
          swMatched++;
          break; // one entity per family
        }
      }
    }
  });
  syncSoftware();

  // ── Match threat actors ───────────────────────────────────────────────────
  const syncGroups = db.transaction(() => {
    for (const [slug, actor] of Object.entries(actorsDict)) {
      const displayName = actor.value || '';
      const description = actor.description || '';
      const meta        = actor.meta || {};
      const synonyms    = Array.isArray(meta.synonyms) ? meta.synonyms : [];
      const refs        = Array.isArray(meta.refs) ? meta.refs : [];
      const country     = meta.country || '';
      const since       = meta.since ? String(meta.since) : '';
      const uuid        = actor.uuid || '';

      const malpediaNames = [displayName, slug, ...synonyms].filter(Boolean);

      for (const row of groupRows) {
        const rowAliases = (() => {
          try { return JSON.parse(row.aliases || '[]'); } catch (_) { return []; }
        })();

        if (entityMatchesMalpedia(row.name, rowAliases, malpediaNames)) {
          stmts.updateGroup.run(
            slug,
            uuid,
            JSON.stringify(refs.slice(0, 20)),   // refs
            mergeAliases(row.aliases, synonyms), // merged aliases
            description,                         // fill desc if empty
            country,                             // fill country if empty
            since,                               // fill first_seen if empty
            row.id,
          );
          tgMatched++;
          break;
        }
      }
    }
  });
  syncGroups();

  // 4. Log the result
  stmts.logSync.run(familiesFetched, actorsFetched, swMatched, tgMatched);
  console.log(`[Malpedia] Done — sw matched: ${swMatched}, tg matched: ${tgMatched}`);

  return { familiesFetched, actorsFetched, swMatched, tgMatched };
}

// ── Last sync status ──────────────────────────────────────────────────────────

function getLastSync() {
  return stmts.lastSync.get() || null;
}

module.exports = { syncMalpedia, getLastSync };
