const express = require('express');
const db = require('../db');
const router = express.Router();

// --- Queries ---
const stmts = {
  latestArticles: db.prepare(`
    SELECT * FROM articles ORDER BY published_at DESC LIMIT ?
  `),
  articlesByVendor: db.prepare(`
    SELECT * FROM articles WHERE vendor = ? ORDER BY published_at DESC LIMIT ?
  `),
  articlesByCategory: db.prepare(`
    SELECT * FROM articles WHERE category = ? ORDER BY published_at DESC LIMIT ?
  `),
  articlesBySource: db.prepare(`
    SELECT * FROM articles WHERE source = ? ORDER BY published_at DESC LIMIT ?
  `),
  searchArticles: db.prepare(`
    SELECT * FROM articles
    WHERE title LIKE ? OR summary LIKE ? OR vendor LIKE ?
    ORDER BY published_at DESC LIMIT ?
  `),
  vendorCounts: db.prepare(`
    SELECT vendor, COUNT(*) as count FROM articles
    WHERE vendor IS NOT NULL
    GROUP BY vendor ORDER BY count DESC
  `),
  categoryCounts: db.prepare(`
    SELECT category, COUNT(*) as count FROM articles
    GROUP BY category ORDER BY count DESC
  `),
  sourceCounts: db.prepare(`
    SELECT source, COUNT(*) as count FROM articles
    GROUP BY source ORDER BY count DESC
  `),
  feedHealth: db.prepare(`SELECT * FROM feed_health ORDER BY source`),
  totalCount: db.prepare(`SELECT COUNT(*) as count FROM articles`),
};

// --- Routes ---

// Homepage
router.get('/', (req, res) => {
  const articles = stmts.latestArticles.all(50);
  const vendors = stmts.vendorCounts.all();
  const categories = stmts.categoryCounts.all();
  const { count } = stmts.totalCount.get();
  res.render('index', { articles, vendors, categories, totalCount: count });
});

// Vendor page
router.get('/vendor/:vendor', (req, res) => {
  const vendor = req.params.vendor;
  const articles = stmts.articlesByVendor.all(vendor, 100);
  res.render('vendor', { vendor, articles });
});

// Category page
router.get('/category/:category', (req, res) => {
  const category = req.params.category;
  const articles = stmts.articlesByCategory.all(category, 100);
  res.render('category', { category, articles });
});

// Source page
router.get('/source/:source', (req, res) => {
  const source = req.params.source;
  const articles = stmts.articlesBySource.all(source, 100);
  res.render('source', { source, articles });
});

// Search
router.get('/search', (req, res) => {
  const q = (req.query.q || '').trim();
  let articles = [];
  if (q) {
    const like = `%${q}%`;
    articles = stmts.searchArticles.all(like, like, like, 100);
  }
  res.render('search', { query: q, articles });
});

// Vendors list
router.get('/vendors', (req, res) => {
  const vendors = stmts.vendorCounts.all();
  res.render('vendors', { vendors });
});

// Sources / feed health
router.get('/sources', (req, res) => {
  const sources = stmts.sourceCounts.all();
  const health = stmts.feedHealth.all();
  res.render('sources', { sources, health });
});

// Health check (JSON)
router.get('/health', (req, res) => {
  const { count } = stmts.totalCount.get();
  res.json({ status: 'ok', articles: count });
});

module.exports = router;
