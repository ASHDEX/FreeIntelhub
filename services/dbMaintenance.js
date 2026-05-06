/**
 * Database Maintenance
 *
 * Keeps SQLite happy on long-running deployments:
 *   - PRAGMA optimize: cheap; safe on every startup.
 *   - PRAGMA wal_checkpoint(TRUNCATE): forces the WAL file back down so the
 *     5-50× WAL bloat we measured doesn't fill the Hostinger disk quota.
 *   - VACUUM: heavier; runs on a weekly cron only, off-peak hour.
 */

const db = require('../db');

function optimize() {
  try {
    db.pragma('optimize');
    db.pragma('wal_checkpoint(TRUNCATE)');
    console.log('[DBMaint] PRAGMA optimize + WAL checkpoint done');
  } catch (err) {
    console.warn('[DBMaint] optimize failed:', err.message);
  }
}

function vacuum() {
  try {
    const before = sizeOnDisk();
    db.exec('VACUUM');
    const after = sizeOnDisk();
    console.log(`[DBMaint] VACUUM done — ${before}MB → ${after}MB`);
  } catch (err) {
    console.warn('[DBMaint] VACUUM failed:', err.message);
  }
}

function sizeOnDisk() {
  try {
    const fs = require('fs');
    const path = require('path');
    const dbPath = process.env.DB_PATH || path.join(__dirname, '..', 'db', 'freeintelhub.sqlite');
    return Math.round(fs.statSync(dbPath).size / (1024 * 1024) * 10) / 10;
  } catch (_) { return null; }
}

module.exports = { optimize, vacuum, sizeOnDisk };
