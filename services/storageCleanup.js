/**
 * Storage Cleanup Service
 *
 * Prunes unbounded tables that the original design left without retention:
 *   - darkweb_hits  (4h scrape cycles fill this fast)
 *   - paste_hits    (paste-site monitoring)
 *   - ioc_geo       (IP geolocation cache; trimmed by last_seen)
 *   - sent_alerts   (per-subscriber-per-article delivery log)
 *
 * Retention windows are configurable via env vars; sensible defaults below.
 * Designed to be safe to run on a small SQLite on shared hosting (Hostinger):
 * each statement is a single bounded DELETE, no full-table scans without an index.
 */

const db = require('../db');

const DW_RETENTION_DAYS         = parseInt(process.env.DW_RETENTION_DAYS,         10) || 60;
const PASTE_RETENTION_DAYS      = parseInt(process.env.PASTE_RETENTION_DAYS,      10) || 30;
const IOC_GEO_RETENTION_DAYS    = parseInt(process.env.IOC_GEO_RETENTION_DAYS,    10) || 90;
const SENT_ALERT_RETENTION_DAYS = parseInt(process.env.SENT_ALERT_RETENTION_DAYS, 10) || 90;

// darkweb_hits.discovered_at is stored in ms epoch
const deleteOldDarkwebHits = db.prepare(`
  DELETE FROM darkweb_hits
  WHERE discovered_at < (strftime('%s','now') - ? * 86400) * 1000
`);

// paste_hits.found_at is a TEXT datetime
const deleteOldPasteHits = db.prepare(`
  DELETE FROM paste_hits
  WHERE found_at < datetime('now', '-' || ? || ' days')
`);

// ioc_geo.last_seen is ms epoch
const deleteOldIocGeo = db.prepare(`
  DELETE FROM ioc_geo
  WHERE last_seen < (strftime('%s','now') - ? * 86400) * 1000
`);

// sent_alerts.sent_at is a TEXT datetime
const deleteOldSentAlerts = db.prepare(`
  DELETE FROM sent_alerts
  WHERE sent_at < datetime('now', '-' || ? || ' days')
`);

function cleanupStorage() {
  const stats = {};
  try { stats.darkweb_hits = deleteOldDarkwebHits.run(DW_RETENTION_DAYS).changes; } catch (e) { stats.darkweb_hits = `err: ${e.message}`; }
  try { stats.paste_hits   = deleteOldPasteHits.run(PASTE_RETENTION_DAYS).changes; } catch (e) { stats.paste_hits   = `err: ${e.message}`; }
  try { stats.ioc_geo      = deleteOldIocGeo.run(IOC_GEO_RETENTION_DAYS).changes; } catch (e) { stats.ioc_geo      = `err: ${e.message}`; }
  try { stats.sent_alerts  = deleteOldSentAlerts.run(SENT_ALERT_RETENTION_DAYS).changes; } catch (e) { stats.sent_alerts  = `err: ${e.message}`; }

  const total = Object.values(stats).filter(v => typeof v === 'number').reduce((a, b) => a + b, 0);
  if (total > 0) console.log('[StorageCleanup] Pruned rows:', stats);
  return stats;
}

module.exports = {
  cleanupStorage,
  DW_RETENTION_DAYS,
  PASTE_RETENTION_DAYS,
  IOC_GEO_RETENTION_DAYS,
  SENT_ALERT_RETENTION_DAYS,
};
