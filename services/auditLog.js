/**
 * Audit Log
 *
 * Lightweight, append-only event recorder. Every interesting state change
 * (login, logout, case create/edit, API key create/use, admin action) writes
 * a row here. Cheap to query, indexed by (created_at) and (actor, created_at).
 *
 * Designed not to throw — failures are logged but never block the request.
 */

const db = require('../db');

const insertAudit = db.prepare(`
  INSERT INTO audit_log (actor, action, target_type, target_id, detail, ip)
  VALUES (?, ?, ?, ?, ?, ?)
`);

function record(opts) {
  try {
    const { actor, action, target_type, target_id, detail, ip } = opts || {};
    if (!action) return;
    insertAudit.run(
      actor || null,
      String(action).slice(0, 64),
      target_type ? String(target_type).slice(0, 32) : null,
      target_id != null ? String(target_id).slice(0, 64) : null,
      detail ? String(detail).slice(0, 512) : null,
      ip ? String(ip).slice(0, 45) : null
    );
  } catch (err) {
    console.warn('[Audit] record failed:', err.message);
  }
}

function clientIp(req) {
  return (req.headers['x-forwarded-for'] || '').split(',')[0].trim()
    || req.socket?.remoteAddress
    || null;
}

const recent = db.prepare(`
  SELECT * FROM audit_log
  ORDER BY created_at DESC
  LIMIT ? OFFSET ?
`);

function getRecent(limit = 100, offset = 0) {
  return recent.all(Math.min(500, limit | 0), offset | 0);
}

const totalCount = db.prepare(`SELECT COUNT(*) c FROM audit_log`);
function getTotal() { return totalCount.get().c; }

module.exports = { record, clientIp, getRecent, getTotal };
