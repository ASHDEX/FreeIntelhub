/**
 * Article Cleanup Service
 * Auto-purges articles older than a configurable number of days.
 */

const db = require('../db');

const RETENTION_DAYS = parseInt(process.env.ARTICLE_RETENTION_DAYS, 10) || 365;

const deleteOldArticles = db.prepare(`
  DELETE FROM articles WHERE published_at < datetime('now', '-' || ? || ' days')
`);

const countOldArticles = db.prepare(`
  SELECT COUNT(*) as count FROM articles WHERE published_at < datetime('now', '-' || ? || ' days')
`);

function cleanupOldArticles() {
  const { count } = countOldArticles.get(RETENTION_DAYS);
  if (count === 0) return;

  deleteOldArticles.run(RETENTION_DAYS);
  console.log(`[Cleanup] Purged ${count} articles older than ${RETENTION_DAYS} days`);
}

module.exports = { cleanupOldArticles, RETENTION_DAYS };
