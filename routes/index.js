const express = require('express');
const crypto = require('crypto');
const rateLimit = require('express-rate-limit');
const db = require('../db');
const feeds = require('../config/feeds.json');
const { CATEGORY_PATTERNS } = require('../services/categorizer');
const sectorConfig = require('../config/sectors.json');
const { sendVerification, isConfigured: smtpConfigured } = require('../services/emailService');
const { getLatestCVEs } = require('../services/cveFetcher');
const { generateRSS } = require('../services/feedGenerator');
const { lookupIOC, PROVIDERS: TI_PROVIDERS } = require('../services/iocLookup');
const router = express.Router();

const BASE_URL = process.env.BASE_URL || 'http://localhost:3000';

// --- Security helpers ---

// Sanitize URL for safe use in href attributes (prevent javascript: protocol XSS)
function safeHref(url) {
  if (!url) return '#';
  const trimmed = url.trim();
  if (/^https?:\/\//i.test(trimmed)) return trimmed;
  if (/^\/[^\/]/.test(trimmed)) return trimmed;
  return '#';
}

// Validate webhook URLs — block SSRF to internal/private networks
function isValidWebhookUrl(urlStr) {
  try {
    const parsed = new URL(urlStr);
    if (parsed.protocol !== 'https:' && parsed.protocol !== 'http:') return false;
    const hostname = parsed.hostname.toLowerCase();
    if (hostname === 'localhost' || hostname === '127.0.0.1' || hostname === '[::1]') return false;
    if (hostname === '0.0.0.0' || hostname === '169.254.169.254') return false;
    if (/^10\./.test(hostname)) return false;
    if (/^172\.(1[6-9]|2\d|3[01])\./.test(hostname)) return false;
    if (/^192\.168\./.test(hostname)) return false;
    if (/^(metadata|internal|consul|vault|etcd|kubernetes)/i.test(hostname)) return false;
    return true;
  } catch (_) {
    return false;
  }
}

// Validate email format
const EMAIL_REGEX = /^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/;
function isValidEmail(email) {
  if (!email || email.length > 254) return false;
  if (!EMAIL_REGEX.test(email)) return false;
  if (/[\r\n]/.test(email)) return false;
  return true;
}

// Mask email for logging (PII protection)
function maskEmail(email) {
  const [local, domain] = email.split('@');
  if (!domain) return '***';
  return local.slice(0, 2) + '***@' + domain;
}

// API-specific rate limit
const apiLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Too many API requests, try again later' },
});

// Email operations rate limit
const emailLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 10,
  standardHeaders: true,
  legacyHeaders: false,
  message: 'Too many email requests, try again later',
});

// Static lists for navbar dropdowns
const NAV_SOURCES = feeds.map(f => f.name);
const NAV_CATEGORIES = Object.keys(CATEGORY_PATTERNS);
const NAV_SECTORS = Object.keys(sectorConfig);

const PER_PAGE = 20;

function getPage(req) {
  const p = parseInt(req.query.page, 10);
  return (p > 0) ? p : 1;
}

function getApiLimit(req) {
  const l = parseInt(req.query.limit, 10);
  return (l > 0 && l <= 100) ? l : 20;
}

// Parse JSON fields for API responses
function enrichArticle(a) {
  const obj = { ...a };
  if (obj.mitre_techniques) {
    try { obj.mitre_techniques = JSON.parse(obj.mitre_techniques); } catch (_) {}
  }
  if (obj.iocs) {
    try { obj.iocs = JSON.parse(obj.iocs); } catch (_) {}
  }
  if (obj.vendors_all) {
    try { obj.vendors_all = JSON.parse(obj.vendors_all); } catch (_) {}
  }
  return obj;
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
  articleById: db.prepare(`SELECT * FROM articles WHERE id = ?`),
  articlesByMitre: db.prepare(`
    SELECT * FROM articles WHERE mitre_techniques LIKE ? ORDER BY published_at DESC LIMIT ? OFFSET ?
  `),
  mitreCount: db.prepare(`
    SELECT COUNT(*) as count FROM articles WHERE mitre_techniques LIKE ?
  `),
  articlesWithIOCs: db.prepare(`
    SELECT * FROM articles WHERE iocs IS NOT NULL ORDER BY published_at DESC LIMIT ? OFFSET ?
  `),
  iocCount: db.prepare(`
    SELECT COUNT(*) as count FROM articles WHERE iocs IS NOT NULL
  `),
  // Trending
  trendingCategories: db.prepare(`
    SELECT category, COUNT(*) as count FROM articles
    WHERE published_at >= datetime('now', '-' || ? || ' days')
    AND category IS NOT NULL
    GROUP BY category ORDER BY count DESC LIMIT 10
  `),
  trendingVendors: db.prepare(`
    SELECT vendor, COUNT(*) as count FROM articles
    WHERE published_at >= datetime('now', '-' || ? || ' days')
    AND vendor IS NOT NULL
    GROUP BY vendor ORDER BY count DESC LIMIT 10
  `),
  trendingSources: db.prepare(`
    SELECT source, COUNT(*) as count FROM articles
    WHERE published_at >= datetime('now', '-' || ? || ' days')
    GROUP BY source ORDER BY count DESC LIMIT 10
  `),
  // Bookmarks
  insertBookmark: db.prepare(`
    INSERT OR IGNORE INTO bookmarks (subscriber_id, article_id) VALUES (?, ?)
  `),
  deleteBookmark: db.prepare(`
    DELETE FROM bookmarks WHERE subscriber_id = ? AND article_id = ?
  `),
  getBookmarks: db.prepare(`
    SELECT a.* FROM articles a
    JOIN bookmarks b ON b.article_id = a.id
    WHERE b.subscriber_id = ?
    ORDER BY b.created_at DESC
  `),
  // Dedup: find similar articles
  findSimilar: db.prepare(`
    SELECT * FROM articles WHERE dedup_hash = ? AND id != ? ORDER BY published_at DESC LIMIT 5
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
  // Webhooks
  insertWebhook: db.prepare(`
    INSERT OR IGNORE INTO webhooks (subscriber_id, webhook_type, webhook_url)
    VALUES (@subscriber_id, @webhook_type, @webhook_url)
  `),
  getWebhooks: db.prepare(`SELECT * FROM webhooks WHERE subscriber_id = ?`),
  deleteWebhook: db.prepare(`DELETE FROM webhooks WHERE id = ? AND subscriber_id = ?`),
};

// --- Inject nav data and helpers into all views ---
router.use((req, res, next) => {
  res.locals.navSources = NAV_SOURCES;
  res.locals.navCategories = NAV_CATEGORIES;
  res.locals.navSectors = NAV_SECTORS;
  res.locals.currentPath = req.path;
  res.locals.safeHref = safeHref;
  // Top vendors for navbar dropdown (cached per request)
  res.locals.vendors = stmts.vendorCounts.all().slice(0, 15);
  next();
});

// =============================================
// Page Routes
// =============================================

// Homepage
router.get('/', async (req, res) => {
  const page = parseInt(req.query.page, 10) || 1;
  const section = req.query.section;

  const HOME_PER_PAGE = Math.min(parseInt(req.query.per_page, 10) || 12, 50);

  // News pagination
  const newsPage = section === 'news' ? page : 1;
  const newsTotal = stmts.latestCount.get().count;
  const articles = stmts.latestArticles.all(HOME_PER_PAGE, (newsPage - 1) * HOME_PER_PAGE);
  const newsPages = Math.ceil(newsTotal / HOME_PER_PAGE);

  // Breach pagination
  const breachPage = section === 'breaches' ? page : 1;
  const breachTotal = stmts.breachCount.get().count;
  const breachArticles = stmts.breachArticles.all(HOME_PER_PAGE, (breachPage - 1) * HOME_PER_PAGE);
  const breachPages = Math.ceil(breachTotal / HOME_PER_PAGE);

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

// MITRE ATT&CK page
router.get('/mitre', (req, res) => {
  const technique = (req.query.technique || '').trim();
  const page = getPage(req);
  let articles = [];
  let total = 0;
  let pages = 0;

  if (technique) {
    const like = `%${technique}%`;
    total = stmts.mitreCount.get(like).count;
    articles = stmts.articlesByMitre.all(like, PER_PAGE, (page - 1) * PER_PAGE);
    pages = Math.ceil(total / PER_PAGE);
  }

  const mitreTechniques = require('../config/mitre.json');
  res.render('mitre', {
    pageTitle: 'MITRE ATT&CK',
    technique, articles, page, pages, total,
    mitreTechniques,
    baseUrl: technique ? `/mitre?technique=${encodeURIComponent(technique)}` : '/mitre',
  });
});

// IOCs page
router.get('/iocs', (req, res) => {
  const page = getPage(req);
  const total = stmts.iocCount.get().count;
  const articles = stmts.articlesWithIOCs.all(PER_PAGE, (page - 1) * PER_PAGE);
  const pages = Math.ceil(total / PER_PAGE);
  res.render('iocs', {
    pageTitle: 'IOC Feed',
    articles, page, pages, total,
    baseUrl: '/iocs',
  });
});

// Trending page
router.get('/trending', (req, res) => {
  res.render('trending', { pageTitle: 'Trending' });
});

// Bookmarks page
router.get('/bookmarks', (req, res) => {
  const token = req.query.token;
  let subscriber = null;
  let bookmarks = [];
  if (token) {
    subscriber = stmts.getSubscriberByToken.get(token);
    if (subscriber) {
      bookmarks = stmts.getBookmarks.all(subscriber.id);
    }
  }
  res.render('bookmarks', { pageTitle: 'Bookmarks', subscriber, bookmarks });
});

// Add bookmark
router.post('/bookmarks/add', (req, res) => {
  const token = req.body.token;
  const articleId = parseInt(req.body.article_id, 10);
  const subscriber = token ? stmts.getSubscriberByToken.get(token) : null;
  if (!subscriber) return res.status(401).json({ error: 'Invalid token' });
  stmts.insertBookmark.run(subscriber.id, articleId);
  res.json({ ok: true });
});

// Remove bookmark
router.post('/bookmarks/remove', (req, res) => {
  const token = req.body.token;
  const articleId = parseInt(req.body.article_id, 10);
  const subscriber = token ? stmts.getSubscriberByToken.get(token) : null;
  if (!subscriber) return res.redirect('/bookmarks');
  stmts.deleteBookmark.run(subscriber.id, articleId);
  res.redirect(`/bookmarks?token=${encodeURIComponent(token)}`);
});

// Sitemap.xml
router.get('/sitemap.xml', (req, res) => {
  const articles = stmts.latestArticles.all(1000, 0);
  const vendorList = stmts.vendorCounts.all();
  const categoryList = stmts.categoryCounts.all();
  const sectorList = stmts.sectorCounts.all();

  const escXml = (s) => String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
  const safeBase = escXml(BASE_URL);

  let xml = '<?xml version="1.0" encoding="UTF-8"?>\n';
  xml += '<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">\n';
  xml += `  <url><loc>${safeBase}/</loc><changefreq>hourly</changefreq><priority>1.0</priority></url>\n`;
  xml += `  <url><loc>${safeBase}/trending</loc><changefreq>hourly</changefreq><priority>0.8</priority></url>\n`;
  xml += `  <url><loc>${safeBase}/vendors</loc><changefreq>daily</changefreq><priority>0.7</priority></url>\n`;
  xml += `  <url><loc>${safeBase}/categories</loc><changefreq>daily</changefreq><priority>0.7</priority></url>\n`;
  xml += `  <url><loc>${safeBase}/sectors</loc><changefreq>daily</changefreq><priority>0.7</priority></url>\n`;
  xml += `  <url><loc>${safeBase}/sources</loc><changefreq>daily</changefreq><priority>0.7</priority></url>\n`;

  for (const v of vendorList) {
    xml += `  <url><loc>${safeBase}/vendor/${encodeURIComponent(v.vendor)}</loc><changefreq>daily</changefreq><priority>0.6</priority></url>\n`;
  }
  for (const c of categoryList) {
    xml += `  <url><loc>${safeBase}/category/${encodeURIComponent(c.category)}</loc><changefreq>daily</changefreq><priority>0.6</priority></url>\n`;
  }
  for (const s of sectorList) {
    xml += `  <url><loc>${safeBase}/sector/${encodeURIComponent(s.sector)}</loc><changefreq>daily</changefreq><priority>0.6</priority></url>\n`;
  }

  xml += '</urlset>';
  res.set('Content-Type', 'application/xml');
  res.send(xml);
});

// =============================================
// Alerts & Webhooks
// =============================================

function generateToken() {
  return crypto.randomBytes(16).toString('hex');
}

// Alerts signup page
router.get('/alerts', (req, res) => {
  const token = req.query.token;
  let subscriber = null;
  let rules = [];
  let webhooks = [];
  if (token) {
    subscriber = stmts.getSubscriberByToken.get(token);
    if (subscriber) {
      rules = stmts.getAlertRules.all(subscriber.id);
      webhooks = stmts.getWebhooks.all(subscriber.id);
    }
  }
  const allVendors = stmts.vendorCounts.all();
  res.render('alerts', {
    pageTitle: 'Alerts',
    subscriber, rules, webhooks, allVendors,
    success: req.query.success, error: req.query.error,
  });
});

// Alerts signup POST
router.post('/alerts/subscribe', emailLimiter, async (req, res) => {
  const email = (req.body.email || '').trim().toLowerCase();
  if (!isValidEmail(email)) {
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
      const v = val.trim().slice(0, 200);
      if (v) stmts.insertAlertRule.run({ subscriber_id: subscriber.id, rule_type: type, rule_value: v });
    }
  }

  // Send verification email
  if (smtpConfigured()) {
    await sendVerification(email, verifyToken);
    res.redirect(`/alerts?token=${encodeURIComponent(token)}&success=subscribed_verify`);
  } else {
    res.redirect(`/alerts?token=${encodeURIComponent(token)}&success=subscribed`);
  }
});

// Add alert rule
router.post('/alerts/add-rule', (req, res) => {
  const token = req.body.token;
  const subscriber = token ? stmts.getSubscriberByToken.get(token) : null;
  if (!subscriber) return res.redirect('/alerts?error=not_found');

  const type = req.body.rule_type;
  const validRuleTypes = ['vendor', 'category', 'sector', 'keyword'];
  const value = (req.body.rule_value || '').trim().slice(0, 200);
  if (validRuleTypes.includes(type) && value) {
    stmts.insertAlertRule.run({ subscriber_id: subscriber.id, rule_type: type, rule_value: value });
  }
  res.redirect(`/alerts?token=${encodeURIComponent(token)}&success=rule_added`);
});

// Delete alert rule
router.post('/alerts/delete-rule', (req, res) => {
  const token = req.body.token;
  const subscriber = token ? stmts.getSubscriberByToken.get(token) : null;
  if (!subscriber) return res.redirect('/alerts?error=not_found');

  stmts.deleteAlertRule.run(req.body.rule_id, subscriber.id);
  res.redirect(`/alerts?token=${encodeURIComponent(token)}&success=rule_removed`);
});

// Add webhook
router.post('/alerts/add-webhook', (req, res) => {
  const token = req.body.token;
  const subscriber = token ? stmts.getSubscriberByToken.get(token) : null;
  if (!subscriber) return res.redirect('/alerts?error=not_found');

  const webhookType = req.body.webhook_type;
  const webhookUrl = (req.body.webhook_url || '').trim().slice(0, 500);
  const validTypes = ['slack', 'discord', 'telegram', 'webhook'];

  if (!validTypes.includes(webhookType) || !webhookUrl) {
    return res.redirect(`/alerts?token=${encodeURIComponent(token)}&error=invalid_webhook`);
  }
  // Telegram allows tg:// shorthand, otherwise require valid external URL
  const isTgShorthand = webhookType === 'telegram' && webhookUrl.startsWith('tg://');
  if (!isTgShorthand && !isValidWebhookUrl(webhookUrl)) {
    return res.redirect(`/alerts?token=${encodeURIComponent(token)}&error=invalid_webhook`);
  }
  stmts.insertWebhook.run({ subscriber_id: subscriber.id, webhook_type: webhookType, webhook_url: webhookUrl });
  res.redirect(`/alerts?token=${encodeURIComponent(token)}&success=webhook_added`);
});

// Delete webhook
router.post('/alerts/delete-webhook', (req, res) => {
  const token = req.body.token;
  const subscriber = token ? stmts.getSubscriberByToken.get(token) : null;
  if (!subscriber) return res.redirect('/alerts?error=not_found');

  stmts.deleteWebhook.run(req.body.webhook_id, subscriber.id);
  res.redirect(`/alerts?token=${encodeURIComponent(token)}&success=webhook_removed`);
});

// Verify email
router.get('/alerts/verify', (req, res) => {
  const verifyToken = req.query.token;
  if (!verifyToken) return res.redirect('/alerts?error=invalid_token');

  const subscriber = stmts.getSubscriberByVerifyToken.get(verifyToken);
  if (!subscriber) return res.redirect('/alerts?error=invalid_token');

  stmts.verifySubscriber.run(subscriber.id);
  res.redirect(`/alerts?token=${encodeURIComponent(subscriber.token)}&success=verified`);
});

// Resend verification email
router.post('/alerts/resend-verify', emailLimiter, async (req, res) => {
  const token = req.body.token;
  const subscriber = token ? stmts.getSubscriberByToken.get(token) : null;
  if (!subscriber) return res.redirect('/alerts?error=not_found');

  if (subscriber.verified) {
    return res.redirect(`/alerts?token=${encodeURIComponent(token)}&success=already_verified`);
  }

  const newVerifyToken = generateToken();
  stmts.resendVerification.run({ verify_token: newVerifyToken }, subscriber.id);
  await sendVerification(subscriber.email, newVerifyToken);
  res.redirect(`/alerts?token=${encodeURIComponent(token)}&success=verification_sent`);
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
    db.prepare(`DELETE FROM webhooks WHERE subscriber_id = ?`).run(subscriber.id);
    stmts.deleteSubscriber.run(subscriber.id);
  }
  res.redirect('/alerts?success=unsubscribed');
});

// =============================================
// REST API — JSON Endpoints
// =============================================

// Apply stricter rate limits to all API routes
router.use('/api', apiLimiter);

// GET /api/articles — List articles with filters
router.get('/api/articles', (req, res) => {
  const limit = getApiLimit(req);
  const page = getPage(req);
  const offset = (page - 1) * limit;

  const vendor = req.query.vendor;
  const category = req.query.category;
  const sector = req.query.sector;
  const source = req.query.source;
  const q = (req.query.q || '').trim();
  const mitre = req.query.mitre;
  const iocsOnly = req.query.iocs === '1';

  let articles, total;

  if (vendor) {
    total = stmts.vendorCount.get(vendor).count;
    articles = stmts.articlesByVendor.all(vendor, limit, offset);
  } else if (category) {
    total = stmts.categoryCount.get(category).count;
    articles = stmts.articlesByCategory.all(category, limit, offset);
  } else if (sector) {
    total = stmts.sectorCount.get(sector).count;
    articles = stmts.articlesBySector.all(sector, limit, offset);
  } else if (source) {
    total = stmts.sourceCount.get(source).count;
    articles = stmts.articlesBySource.all(source, limit, offset);
  } else if (q) {
    const like = `%${q}%`;
    total = stmts.searchCount.get(like, like, like).count;
    articles = stmts.searchArticles.all(like, like, like, limit, offset);
  } else if (mitre) {
    const like = `%${mitre}%`;
    total = stmts.mitreCount.get(like).count;
    articles = stmts.articlesByMitre.all(like, limit, offset);
  } else if (iocsOnly) {
    total = stmts.iocCount.get().count;
    articles = stmts.articlesWithIOCs.all(limit, offset);
  } else {
    total = stmts.latestCount.get().count;
    articles = stmts.latestArticles.all(limit, offset);
  }

  res.json({
    data: articles.map(enrichArticle),
    pagination: { page, limit, total, pages: Math.ceil(total / limit) },
  });
});

// GET /api/articles/:id — Single article
router.get('/api/articles/:id', (req, res) => {
  const id = parseInt(req.params.id, 10);
  const article = stmts.articleById.get(id);
  if (!article) return res.status(404).json({ error: 'Article not found' });
  res.json({ data: enrichArticle(article) });
});

// GET /api/vendors — Vendor list with counts
router.get('/api/vendors', (req, res) => {
  res.json({ data: stmts.vendorCounts.all() });
});

// GET /api/categories — Category list with counts
router.get('/api/categories', (req, res) => {
  res.json({ data: stmts.categoryCounts.all() });
});

// GET /api/sectors — Sector list with counts
router.get('/api/sectors', (req, res) => {
  res.json({ data: stmts.sectorCounts.all() });
});

// GET /api/sources — Source list with health data
router.get('/api/sources', (req, res) => {
  const sources = stmts.sourceCounts.all();
  const health = stmts.feedHealth.all();
  const healthMap = {};
  for (const h of health) healthMap[h.source] = h;
  const data = sources.map(s => ({ ...s, health: healthMap[s.source] || null }));
  res.json({ data });
});

// GET /api/iocs — Articles containing IOCs
router.get('/api/iocs', (req, res) => {
  const limit = getApiLimit(req);
  const page = getPage(req);
  const offset = (page - 1) * limit;
  const total = stmts.iocCount.get().count;
  const articles = stmts.articlesWithIOCs.all(limit, offset);
  res.json({
    data: articles.map(enrichArticle),
    pagination: { page, limit, total, pages: Math.ceil(total / limit) },
  });
});

// GET /api/mitre — Articles by MITRE ATT&CK technique
router.get('/api/mitre', (req, res) => {
  const technique = (req.query.technique || '').trim();
  const limit = getApiLimit(req);
  const page = getPage(req);
  const offset = (page - 1) * limit;

  if (!technique) {
    return res.json({ data: [], pagination: { page, limit, total: 0, pages: 0 } });
  }

  const like = `%${technique}%`;
  const total = stmts.mitreCount.get(like).count;
  const articles = stmts.articlesByMitre.all(like, limit, offset);
  res.json({
    data: articles.map(enrichArticle),
    pagination: { page, limit, total, pages: Math.ceil(total / limit) },
  });
});

// GET /api/trending — Trending data for charts
router.get('/api/trending', (req, res) => {
  const days = parseInt(req.query.days, 10) || 7;
  const safeDays = Math.min(Math.max(days, 1), 90);
  const categories = stmts.trendingCategories.all(safeDays);
  const vendors = stmts.trendingVendors.all(safeDays);
  const sources = stmts.trendingSources.all(safeDays);
  res.json({ categories, vendors, sources, days: safeDays });
});

// GET /api/articles/:id/similar — Find duplicate/similar articles
router.get('/api/articles/:id/similar', (req, res) => {
  const id = parseInt(req.params.id, 10);
  const article = stmts.articleById.get(id);
  if (!article || !article.dedup_hash) return res.json({ data: [] });
  const similar = stmts.findSimilar.all(article.dedup_hash, id);
  res.json({ data: similar.map(enrichArticle) });
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

// =============================================
// IOC Lookup
// =============================================

// IOC Lookup page
router.get('/lookup', (req, res) => {
  res.render('lookup', { pageTitle: 'IOC Lookup', providers: TI_PROVIDERS });
});

// IOC Lookup API — keys are used once and discarded
router.post('/api/lookup', apiLimiter, async (req, res) => {
  const iocValue = (req.body.ioc || '').trim();
  if (!iocValue || iocValue.length > 2048) {
    return res.status(400).json({ error: 'Invalid IOC value' });
  }

  const apiKeys = {};
  const keys = req.body.keys || {};
  for (const [provider, key] of Object.entries(keys)) {
    const k = String(key).trim();
    if (k && k.length <= 256 && TI_PROVIDERS[provider]) {
      apiKeys[provider] = k;
    }
  }

  const selectedProviders = Array.isArray(req.body.providers)
    ? req.body.providers.filter(p => typeof p === 'string' && TI_PROVIDERS[p])
    : null;

  try {
    const result = await lookupIOC(iocValue, apiKeys, selectedProviders);
    res.json(result);
  } catch (err) {
    res.status(500).json({ error: 'Lookup failed' });
  }
});

// =============================================
// RSS Feed Endpoints
// =============================================

// GET /feed/all.xml — All articles
router.get('/feed/all.xml', (req, res) => {
  const articles = stmts.latestArticles.all(50, 0);
  res.set('Content-Type', 'application/rss+xml');
  res.send(generateRSS(
    'FreeIntelHub — All Articles',
    'Latest cybersecurity threat intelligence articles',
    `${BASE_URL}/feed/all.xml`,
    articles
  ));
});

// GET /feed/vendor/:vendor.xml
router.get('/feed/vendor/:vendor.xml', (req, res) => {
  const vendor = req.params.vendor;
  const articles = stmts.articlesByVendor.all(vendor, 50, 0);
  res.set('Content-Type', 'application/rss+xml');
  res.send(generateRSS(
    `FreeIntelHub — ${vendor}`,
    `Latest cybersecurity articles about ${vendor}`,
    `${BASE_URL}/feed/vendor/${encodeURIComponent(vendor)}.xml`,
    articles
  ));
});

// GET /feed/category/:category.xml
router.get('/feed/category/:category.xml', (req, res) => {
  const category = req.params.category;
  const articles = stmts.articlesByCategory.all(category, 50, 0);
  res.set('Content-Type', 'application/rss+xml');
  res.send(generateRSS(
    `FreeIntelHub — ${category}`,
    `Latest ${category} articles`,
    `${BASE_URL}/feed/category/${encodeURIComponent(category)}.xml`,
    articles
  ));
});

// GET /feed/sector/:sector.xml
router.get('/feed/sector/:sector.xml', (req, res) => {
  const sector = req.params.sector;
  const articles = stmts.articlesBySector.all(sector, 50, 0);
  res.set('Content-Type', 'application/rss+xml');
  res.send(generateRSS(
    `FreeIntelHub — ${sector}`,
    `Latest cybersecurity articles for the ${sector} sector`,
    `${BASE_URL}/feed/sector/${encodeURIComponent(sector)}.xml`,
    articles
  ));
});

// GET /feed/source/:source.xml
router.get('/feed/source/:source.xml', (req, res) => {
  const source = req.params.source;
  const articles = stmts.articlesBySource.all(source, 50, 0);
  res.set('Content-Type', 'application/rss+xml');
  res.send(generateRSS(
    `FreeIntelHub — ${source}`,
    `Articles from ${source}`,
    `${BASE_URL}/feed/source/${encodeURIComponent(source)}.xml`,
    articles
  ));
});

// GET /feed/iocs.xml — Articles with IOCs
router.get('/feed/iocs.xml', (req, res) => {
  const articles = stmts.articlesWithIOCs.all(50, 0);
  res.set('Content-Type', 'application/rss+xml');
  res.send(generateRSS(
    'FreeIntelHub — IOC Feed',
    'Articles containing Indicators of Compromise',
    `${BASE_URL}/feed/iocs.xml`,
    articles
  ));
});

module.exports = router;
