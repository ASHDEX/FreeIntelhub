const express = require('express');
const crypto = require('crypto');
const db = require('../db');
const feeds = require('../config/feeds.json');
const { CATEGORY_PATTERNS } = require('../services/categorizer');
const sectorConfig = require('../config/sectors.json');
const { sendVerification, isConfigured: smtpConfigured } = require('../services/emailService');
const { getLatestCVEs } = require('../services/cveFetcher');
const router = express.Router();

// Static lists for navbar dropdowns
const NAV_SOURCES = feeds.map(f => f.name);
const NAV_CATEGORIES = Object.keys(CATEGORY_PATTERNS);
const NAV_SECTORS = Object.keys(sectorConfig);

const PER_PAGE = 20;

function getPage(req) {
  const p = parseInt(req.query.page, 10);
  return (p > 0) ? p : 1;
}

// --- Queries ---
const stmts = {
  latestArticles: db.prepare(`
    SELECT * FROM articles ORDER BY published_at DESC LIMIT ? OFFSET ?
  `),
  latestCount: db.prepare(`
    SELECT COUNT(*) as count FROM articles
  `),
  articlesByVendor: db.prepare(`
    SELECT * FROM articles WHERE vendor = ? ORDER BY published_at DESC LIMIT ? OFFSET ?
  `),
  vendorCount: db.prepare(`
    SELECT COUNT(*) as count FROM articles WHERE vendor = ?
  `),
  articlesByCategory: db.prepare(`
    SELECT * FROM articles WHERE category = ? ORDER BY published_at DESC LIMIT ? OFFSET ?
  `),
  categoryCount: db.prepare(`
    SELECT COUNT(*) as count FROM articles WHERE category = ?
  `),
  articlesBySource: db.prepare(`
    SELECT * FROM articles WHERE source = ? ORDER BY published_at DESC LIMIT ? OFFSET ?
  `),
  sourceCount: db.prepare(`
    SELECT COUNT(*) as count FROM articles WHERE source = ?
  `),
  searchArticles: db.prepare(`
    SELECT * FROM articles
    WHERE title LIKE ? OR summary LIKE ? OR vendor LIKE ?
    ORDER BY published_at DESC LIMIT ? OFFSET ?
  `),
  searchCount: db.prepare(`
    SELECT COUNT(*) as count FROM articles
    WHERE title LIKE ? OR summary LIKE ? OR vendor LIKE ?
  `),
  breachArticles: db.prepare(`
    SELECT * FROM articles WHERE category = 'Data Breach' ORDER BY published_at DESC LIMIT ? OFFSET ?
  `),
  breachCount: db.prepare(`
    SELECT COUNT(*) as count FROM articles WHERE category = 'Data Breach'
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
  articlesBySector: db.prepare(`
    SELECT * FROM articles WHERE sector = ? ORDER BY published_at DESC LIMIT ? OFFSET ?
  `),
  sectorCount: db.prepare(`
    SELECT COUNT(*) as count FROM articles WHERE sector = ?
  `),
  sectorCounts: db.prepare(`
    SELECT sector, COUNT(*) as count FROM articles
    WHERE sector IS NOT NULL
    GROUP BY sector ORDER BY count DESC
  `),
  feedHealth: db.prepare(`SELECT * FROM feed_health ORDER BY source`),
  totalCount: db.prepare(`SELECT COUNT(*) as count FROM articles`),
  suggestions: db.prepare(`
    SELECT id, title, vendor, category, link FROM articles
    WHERE title LIKE ? OR vendor LIKE ?
    ORDER BY published_at DESC LIMIT 8
  `),
  // Alert system
  insertSubscriber: db.prepare(`
    INSERT INTO subscribers (email, daily_newsletter, token, verified, verify_token)
    VALUES (@email, @newsletter, @token, @verified, @verify_token)
    ON CONFLICT(email) DO UPDATE SET daily_newsletter = @newsletter, token = @token, verify_token = @verify_token
  `),
  getSubscriberByToken: db.prepare(`SELECT * FROM subscribers WHERE token = ?`),
  getSubscriberByVerifyToken: db.prepare(`SELECT * FROM subscribers WHERE verify_token = ?`),
  verifySubscriber: db.prepare(`UPDATE subscribers SET verified = 1, verify_token = NULL WHERE id = ?`),
  resendVerification: db.prepare(`UPDATE subscribers SET verify_token = @verify_token WHERE id = ?`),
  insertAlertRule: db.prepare(`
    INSERT OR IGNORE INTO alert_rules (subscriber_id, rule_type, rule_value)
    VALUES (@subscriber_id, @rule_type, @rule_value)
  `),
  getAlertRules: db.prepare(`SELECT * FROM alert_rules WHERE subscriber_id = ?`),
  deleteAlertRule: db.prepare(`DELETE FROM alert_rules WHERE id = ? AND subscriber_id = ?`),
  deleteSubscriber: db.prepare(`DELETE FROM subscribers WHERE id = ?`),
};

// --- Inject nav data into all views ---
router.use((req, res, next) => {
  res.locals.navSources = NAV_SOURCES;
  res.locals.navCategories = NAV_CATEGORIES;
  res.locals.navSectors = NAV_SECTORS;
  res.locals.currentPath = req.path;
  // Top vendors for navbar dropdown (cached per request)
  res.locals.vendors = stmts.vendorCounts.all().slice(0, 15);
  next();
});

// --- Routes ---

// Homepage
router.get('/', async (req, res) => {
  const page = parseInt(req.query.page, 10) || 1;
  const section = req.query.section;

  // News pagination
  const newsPage = section === 'news' ? page : 1;
  const newsTotal = stmts.latestCount.get().count;
  const articles = stmts.latestArticles.all(PER_PAGE, (newsPage - 1) * PER_PAGE);
  const newsPages = Math.ceil(newsTotal / PER_PAGE);

  // Breach pagination
  const breachPage = section === 'breaches' ? page : 1;
  const breachTotal = stmts.breachCount.get().count;
  const breachArticles = stmts.breachArticles.all(PER_PAGE, (breachPage - 1) * PER_PAGE);
  const breachPages = Math.ceil(breachTotal / PER_PAGE);

  const vendors = stmts.vendorCounts.all();
  const categories = stmts.categoryCounts.all();
  const { count } = stmts.totalCount.get();

  // Fetch latest CVEs for ticker
  const cves = await getLatestCVEs();

  res.render('index', {
    articles, newsPage, newsPages,
    breachArticles, breachPage, breachPages,
    vendors, categories, totalCount: count, cves,
  });
});

// Vendor page
router.get('/vendor/:vendor', (req, res) => {
  const vendor = req.params.vendor;
  const page = getPage(req);
  const total = stmts.vendorCount.get(vendor).count;
  const articles = stmts.articlesByVendor.all(vendor, PER_PAGE, (page - 1) * PER_PAGE);
  const pages = Math.ceil(total / PER_PAGE);
  res.render('vendor', { vendor, articles, page, pages, baseUrl: `/vendor/${encodeURIComponent(vendor)}` });
});

// Category page
router.get('/category/:category', (req, res) => {
  const category = req.params.category;
  const page = getPage(req);
  const total = stmts.categoryCount.get(category).count;
  const articles = stmts.articlesByCategory.all(category, PER_PAGE, (page - 1) * PER_PAGE);
  const pages = Math.ceil(total / PER_PAGE);
  res.render('category', { category, articles, page, pages, baseUrl: `/category/${encodeURIComponent(category)}` });
});

// Source page
router.get('/source/:source', (req, res) => {
  const source = req.params.source;
  const page = getPage(req);
  const total = stmts.sourceCount.get(source).count;
  const articles = stmts.articlesBySource.all(source, PER_PAGE, (page - 1) * PER_PAGE);
  const pages = Math.ceil(total / PER_PAGE);
  res.render('source', { source, articles, page, pages, baseUrl: `/source/${encodeURIComponent(source)}` });
});

// Search
router.get('/search', (req, res) => {
  const q = (req.query.q || '').trim();
  const page = getPage(req);
  let articles = [];
  let pages = 0;
  if (q) {
    const like = `%${q}%`;
    const total = stmts.searchCount.get(like, like, like).count;
    articles = stmts.searchArticles.all(like, like, like, PER_PAGE, (page - 1) * PER_PAGE);
    pages = Math.ceil(total / PER_PAGE);
  }
  res.render('search', { query: q, articles, page, pages, baseUrl: `/search?q=${encodeURIComponent(q)}` });
});

// Sector page
router.get('/sector/:sector', (req, res) => {
  const sector = req.params.sector;
  const page = getPage(req);
  const total = stmts.sectorCount.get(sector).count;
  const articles = stmts.articlesBySector.all(sector, PER_PAGE, (page - 1) * PER_PAGE);
  const pages = Math.ceil(total / PER_PAGE);
  res.render('sector', { sector, articles, page, pages, baseUrl: `/sector/${encodeURIComponent(sector)}` });
});

// Sectors index
router.get('/sectors', (req, res) => {
  const sectors = stmts.sectorCounts.all();
  res.render('sectors', { sectors, pageTitle: 'Sectors' });
});

// Vendors list
router.get('/vendors', (req, res) => {
  const vendors = stmts.vendorCounts.all();
  res.render('vendors', { vendors, pageTitle: 'Vendors' });
});

// Categories index
router.get('/categories', (req, res) => {
  const categories = stmts.categoryCounts.all();
  res.render('categories', { categories, pageTitle: 'News Types' });
});

// Sources / feed health
router.get('/sources', (req, res) => {
  const sources = stmts.sourceCounts.all();
  const health = stmts.feedHealth.all();
  res.render('sources', { sources, health, pageTitle: 'Sources' });
});

// --- Alerts ---
function generateToken() {
  return crypto.randomBytes(16).toString('hex');
}

// Alerts signup page
router.get('/alerts', (req, res) => {
  const token = req.query.token;
  let subscriber = null;
  let rules = [];
  if (token) {
    subscriber = stmts.getSubscriberByToken.get(token);
    if (subscriber) rules = stmts.getAlertRules.all(subscriber.id);
  }
  const allVendors = stmts.vendorCounts.all();
  res.render('alerts', {
    pageTitle: 'Alerts',
    subscriber, rules, allVendors,
    success: req.query.success, error: req.query.error,
  });
});

// Alerts signup POST
router.post('/alerts/subscribe', async (req, res) => {
  const email = (req.body.email || '').trim().toLowerCase();
  if (!email || !email.includes('@')) {
    return res.redirect('/alerts?error=invalid_email');
  }

  const newsletter = req.body.newsletter === 'on' ? 1 : 0;
  const token = generateToken();
  const verifyToken = generateToken();

  // If SMTP is configured, require verification; otherwise auto-verify
  const verified = smtpConfigured() ? 0 : 1;

  stmts.insertSubscriber.run({ email, newsletter, token, verified, verify_token: verifyToken });
  const subscriber = stmts.getSubscriberByToken.get(token);

  // Process alert rules from the form
  const types = ['vendor', 'category', 'sector', 'keyword'];
  for (const type of types) {
    const values = req.body[type];
    if (!values) continue;
    const arr = Array.isArray(values) ? values : [values];
    for (const val of arr) {
      const v = val.trim();
      if (v) stmts.insertAlertRule.run({ subscriber_id: subscriber.id, rule_type: type, rule_value: v });
    }
  }

  // Send verification email
  if (smtpConfigured()) {
    await sendVerification(email, verifyToken);
    res.redirect(`/alerts?token=${token}&success=subscribed_verify`);
  } else {
    res.redirect(`/alerts?token=${token}&success=subscribed`);
  }
});

// Add alert rule
router.post('/alerts/add-rule', (req, res) => {
  const token = req.body.token;
  const subscriber = token ? stmts.getSubscriberByToken.get(token) : null;
  if (!subscriber) return res.redirect('/alerts?error=not_found');

  const type = req.body.rule_type;
  const value = (req.body.rule_value || '').trim();
  if (type && value) {
    stmts.insertAlertRule.run({ subscriber_id: subscriber.id, rule_type: type, rule_value: value });
  }
  res.redirect(`/alerts?token=${token}&success=rule_added`);
});

// Delete alert rule
router.post('/alerts/delete-rule', (req, res) => {
  const token = req.body.token;
  const subscriber = token ? stmts.getSubscriberByToken.get(token) : null;
  if (!subscriber) return res.redirect('/alerts?error=not_found');

  stmts.deleteAlertRule.run(req.body.rule_id, subscriber.id);
  res.redirect(`/alerts?token=${token}&success=rule_removed`);
});

// Verify email
router.get('/alerts/verify', (req, res) => {
  const verifyToken = req.query.token;
  if (!verifyToken) return res.redirect('/alerts?error=invalid_token');

  const subscriber = stmts.getSubscriberByVerifyToken.get(verifyToken);
  if (!subscriber) return res.redirect('/alerts?error=invalid_token');

  stmts.verifySubscriber.run(subscriber.id);
  res.redirect(`/alerts?token=${subscriber.token}&success=verified`);
});

// Resend verification email
router.post('/alerts/resend-verify', async (req, res) => {
  const token = req.body.token;
  const subscriber = token ? stmts.getSubscriberByToken.get(token) : null;
  if (!subscriber) return res.redirect('/alerts?error=not_found');

  if (subscriber.verified) {
    return res.redirect(`/alerts?token=${token}&success=already_verified`);
  }

  const newVerifyToken = generateToken();
  stmts.resendVerification.run({ verify_token: newVerifyToken }, subscriber.id);
  await sendVerification(subscriber.email, newVerifyToken);
  res.redirect(`/alerts?token=${token}&success=verification_sent`);
});

// Unsubscribe (supports both POST and GET for email links)
router.get('/alerts/unsubscribe', (req, res) => {
  const token = req.query.token;
  if (!token) return res.redirect('/alerts');
  const subscriber = stmts.getSubscriberByToken.get(token);
  if (subscriber) {
    res.render('unsubscribe', { pageTitle: 'Unsubscribe', subscriber });
  } else {
    res.redirect('/alerts?success=unsubscribed');
  }
});

router.post('/alerts/unsubscribe', (req, res) => {
  const token = req.body.token;
  const subscriber = token ? stmts.getSubscriberByToken.get(token) : null;
  if (subscriber) {
    db.prepare(`DELETE FROM alert_rules WHERE subscriber_id = ?`).run(subscriber.id);
    stmts.deleteSubscriber.run(subscriber.id);
  }
  res.redirect('/alerts?success=unsubscribed');
});

// Search suggestions API (JSON)
router.get('/api/suggest', (req, res) => {
  const q = (req.query.q || '').trim();
  if (q.length < 2) return res.json([]);
  const like = `%${q}%`;
  const results = stmts.suggestions.all(like, like);
  res.json(results);
});

// CVE ticker API (JSON)
router.get('/api/cves', async (req, res) => {
  const cves = await getLatestCVEs();
  res.json(cves);
});

// Health check (JSON)
router.get('/health', (req, res) => {
  const { count } = stmts.totalCount.get();
  res.json({ status: 'ok', articles: count });
});

module.exports = router;
