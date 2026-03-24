const express = require('express');
const crypto = require('crypto');
const rateLimit = require('express-rate-limit');
const db = require('../db');
const feeds = require('../config/feeds.json');
const { CATEGORY_PATTERNS } = require('../services/categorizer');
const sectorConfig = require('../config/sectors.json');
const { sendVerification, isConfigured: smtpConfigured } = require('../services/emailService');
const { getLatestCVEs, getTickerCVEs, lookupCVE, fullCVELookup, CVE_ID_REGEX } = require('../services/cveFetcher');
const { generateRSS } = require('../services/feedGenerator');
const { lookupThreatIntel } = require('../services/threatIntel');
const { hashToken, encryptWebhookUrl } = require('../services/crypto');
const { getAiContext } = require('../services/aiContext');

const threatmapConfig = require('../config/threatmap.json');
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
function isPrivateIP(ip) {
  // Normalize IPv4-mapped IPv6 (::ffff:127.0.0.1 → 127.0.0.1)
  const v4 = ip.replace(/^::ffff:/i, '');
  if (v4 === '127.0.0.1' || v4 === '0.0.0.0' || v4 === '::1' || v4 === '0') return true;
  if (/^10\./.test(v4)) return true;
  if (/^172\.(1[6-9]|2\d|3[01])\./.test(v4)) return true;
  if (/^192\.168\./.test(v4)) return true;
  if (/^169\.254\./.test(v4)) return true;
  if (/^(fc|fd|fe80)/i.test(ip)) return true; // IPv6 private/link-local
  return false;
}

function isValidWebhookUrl(urlStr) {
  try {
    const parsed = new URL(urlStr);
    if (parsed.protocol !== 'https:' && parsed.protocol !== 'http:') return false;
    const hostname = parsed.hostname.toLowerCase().replace(/^\[|\]$/g, '');
    if (hostname === 'localhost') return false;
    if (/^(metadata|internal|consul|vault|etcd|kubernetes)/i.test(hostname)) return false;
    // Block raw IP addresses (decimal, hex, octal encodings)
    if (/^\d+$/.test(hostname)) return false; // decimal IP like 2130706433
    if (/^0x/i.test(hostname)) return false;  // hex IP like 0x7f000001
    if (/^0\d/.test(hostname)) return false;  // octal IP like 0177.0.0.1
    // Check if hostname is an IP and validate it
    if (/^[\d.:[\]]+$/.test(hostname) && isPrivateIP(hostname)) return false;
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
  resendVerification: db.prepare(`UPDATE subscribers SET verify_token = @verify_token WHERE id = @id`),
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
  // Nav stats — pre-compiled so they're not re-parsed on every request
  navArticles24h: db.prepare(`SELECT COUNT(*) as c FROM articles WHERE published_at >= datetime('now','-1 day')`),
  navCveTotal:    db.prepare(`SELECT COUNT(*) as c FROM articles WHERE title LIKE '%CVE-%'`),
  navHighCount:   db.prepare(`SELECT COUNT(*) as c FROM articles WHERE category IN ('Ransomware','Data Breach','Vulnerability','Exploit') AND published_at >= datetime('now','-7 days')`),
  // Homepage metric cards
  homepageArticles24h:  db.prepare(`SELECT COUNT(*) as c FROM articles WHERE published_at >= datetime('now','-1 day')`),
  homepageIocArticles24h: db.prepare(`SELECT COUNT(*) as c FROM articles WHERE iocs IS NOT NULL AND published_at >= datetime('now','-1 day')`),
  homepageGroups7d: db.prepare(`SELECT COUNT(DISTINCT atg.threat_group_id) as c FROM article_threat_groups atg JOIN articles a ON a.id = atg.article_id WHERE a.published_at >= datetime('now','-7 days')`),
  // /api/suggest — entity typeahead
  suggestGroups:   db.prepare(`SELECT name FROM threat_groups WHERE name LIKE ? ORDER BY name LIMIT 3`),
  suggestSoftware: db.prepare(`SELECT name FROM malware_software WHERE name LIKE ? ORDER BY name LIMIT 3`),
  suggestCampaigns: db.prepare(`SELECT name FROM campaigns WHERE name LIKE ? ORDER BY name LIMIT 3`),
  // checkApiKey — API key validation and rate counting
  apiKeyByHash:    db.prepare(`SELECT id, key_hash, requests_today, last_reset FROM api_keys WHERE key_hash = ?`),
  apiKeyResetCount: db.prepare(`UPDATE api_keys SET requests_today = 1, last_reset = ? WHERE id = ?`),
  apiKeyIncrCount:  db.prepare(`UPDATE api_keys SET requests_today = requests_today + 1 WHERE id = ?`),
  // Search source list
  allSources: db.prepare(`SELECT DISTINCT source FROM articles ORDER BY source`),
};

// Vendor list cache — 60 second TTL, eliminates full GROUP BY scan on every request
let _vendorsCache = null;
let _vendorsCachedAt = 0;
function getNavVendors() {
  const now = Date.now();
  if (_vendorsCache && (now - _vendorsCachedAt) < 60000) return _vendorsCache;
  try {
    _vendorsCache = stmts.vendorCounts.all().slice(0, 15);
  } catch (_) {
    _vendorsCache = [];
  }
  _vendorsCachedAt = now;
  return _vendorsCache;
}

// Nav stats cache — 60 second TTL, avoids running 3 count queries on every request
let _navStatsCache = null;
let _navStatsCachedAt = 0;
function getNavStats() {
  const now = Date.now();
  if (_navStatsCache && (now - _navStatsCachedAt) < 60000) return _navStatsCache;
  try {
    _navStatsCache = {
      articles24h: stmts.navArticles24h.get().c,
      cveTotal:    stmts.navCveTotal.get().c,
      highCount:   stmts.navHighCount.get().c,
    };
  } catch (_) {
    _navStatsCache = { articles24h: 0, cveTotal: 0, highCount: 0 };
  }
  _navStatsCachedAt = now;
  return _navStatsCache;
}

// API key check — applied to all /api/ routes (passthrough if no key header)
// Uses wrapper so the hoisted function declaration is resolved at call time
router.use('/api/', (req, res, next) => checkApiKey(req, res, next));

// --- Inject nav data and helpers into all views ---
router.use((req, res, next) => {
  res.locals.navSources = NAV_SOURCES;
  res.locals.navCategories = NAV_CATEGORIES;
  res.locals.navSectors = NAV_SECTORS;
  res.locals.currentPath = req.path;
  res.locals.safeHref = safeHref;
  res.locals.maskEmail = maskEmail;
  // Top vendors for navbar dropdown (60s TTL cache)
  res.locals.vendors = getNavVendors();
  // Quick stats for sidebar top bar (served from 60s TTL cache)
  res.locals.navStats = getNavStats();
  next();
});

// =============================================
// Page Routes
// =============================================

// Landing page
router.get('/', (req, res) => {
  const totalArticles = stmts.totalCount.get().count;
  const threatGroupCount = db.prepare('SELECT COUNT(*) as count FROM threat_groups').get().count;
  const sourceCount = feeds.length;
  res.render('landing', { totalArticles, threatGroupCount, sourceCount });
});

// Threat Feed
router.get('/feed', async (req, res) => {
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

  // Fetch recently-published CVEs for ticker (last 30 days, newest first)
  const cves = await getTickerCVEs();

  // Homepage metric cards
  const articles24h = stmts.homepageArticles24h.get().c;
  const iocArticles24h = stmts.homepageIocArticles24h.get().c;
  const threatGroups7d = stmts.homepageGroups7d.get().c;

  res.render('index', {
    pageTitle: 'Threat Feed',
    articles, newsPage, newsPages,
    breachArticles, breachPage, breachPages,
    vendors, categories, totalCount: count, cves,
    articles24h, iocArticles24h, threatGroups7d,
    cveCount: cves ? cves.length : 0,
  });
});

// Vendor page
router.get('/vendor/:vendor', (req, res) => {
  const vendor = req.params.vendor;
  const page = getPage(req);
  const total = stmts.vendorCount.get(vendor).count;
  const articles = stmts.articlesByVendor.all(vendor, PER_PAGE, (page - 1) * PER_PAGE);
  const pages = Math.ceil(total / PER_PAGE);
  res.render('vendor', { pageTitle: vendor, vendor, articles, page, pages, baseUrl: `/vendor/${encodeURIComponent(vendor)}` });
});

// Category page
router.get('/category/:category', (req, res) => {
  const category = req.params.category;
  const page = getPage(req);
  const total = stmts.categoryCount.get(category).count;
  const articles = stmts.articlesByCategory.all(category, PER_PAGE, (page - 1) * PER_PAGE);
  const pages = Math.ceil(total / PER_PAGE);
  res.render('category', { pageTitle: category, category, articles, page, pages, baseUrl: `/category/${encodeURIComponent(category)}` });
});

// Source page
router.get('/source/:source', (req, res) => {
  const source = req.params.source;
  const page = getPage(req);
  const total = stmts.sourceCount.get(source).count;
  const articles = stmts.articlesBySource.all(source, PER_PAGE, (page - 1) * PER_PAGE);
  const pages = Math.ceil(total / PER_PAGE);
  res.render('source', { pageTitle: source, source, articles, page, pages, baseUrl: `/source/${encodeURIComponent(source)}` });
});

// Search (with advanced filters)
router.get('/search', async (req, res) => {
  const q = (req.query.q || '').trim();
  const page = getPage(req);
  const dateFrom = (req.query.dateFrom || '').trim();
  const dateTo = (req.query.dateTo || '').trim();
  const sector = (req.query.sector || '').trim();
  const source = (req.query.source || '').trim();
  const tlp = (req.query.tlp || '').trim().toUpperCase();
  const highRiskOnly = req.query.highRisk === '1';

  // If query is a CVE ID, redirect to the full vulnerability lookup page
  if (q && CVE_ID_REGEX.test(q)) {
    return res.redirect(`/vulnerability?cve=${encodeURIComponent(q.toUpperCase())}`);
  }

  let articles = [];
  let pages = 0;
  let usedFTS = false;
  const hasFilters = dateFrom || dateTo || sector || source || tlp || highRiskOnly;

  const allSectors = stmts.sectorCounts.all().map(r => r.sector).filter(Boolean);
  const allSources = stmts.allSources.all().map(r => r.source);

  if (q || hasFilters) {
    const conditions = [];
    const params = [];

    if (q) {
      // Try FTS5 first for better full-text search
      try {
        // Sanitize FTS5 input to prevent query syntax injection (VULN-09)
        const ftsQ = '"' + q.replace(/"/g, '').replace(/[*^]/g, '') + '"';
        // Validate the FTS5 query by running a test first
        db.prepare(`SELECT rowid FROM articles_fts WHERE articles_fts MATCH ? LIMIT 1`).get(ftsQ);
        conditions.push(`id IN (SELECT rowid FROM articles_fts WHERE articles_fts MATCH ?)`);
        params.push(ftsQ);
        usedFTS = true;
      } catch (_) {
        // FTS5 query syntax error — fall back to LIKE
        const like = `%${q}%`;
        conditions.push(`(title LIKE ? OR summary LIKE ? OR vendor LIKE ?)`);
        params.push(like, like, like);
      }
    }

    if (dateFrom) { conditions.push(`published_at >= ?`); params.push(dateFrom + 'T00:00:00'); }
    if (dateTo) { conditions.push(`published_at <= ?`); params.push(dateTo + 'T23:59:59'); }
    if (sector) { conditions.push(`sector = ?`); params.push(sector); }
    if (source) { conditions.push(`source = ?`); params.push(source); }
    if (tlp && ['WHITE', 'GREEN', 'AMBER', 'RED'].includes(tlp)) { conditions.push(`tlp = ?`); params.push(tlp); }
    if (highRiskOnly) { conditions.push(`(iocs IS NOT NULL OR mitre_techniques IS NOT NULL OR title LIKE ? OR category IN ('Ransomware','Data Breach','Vulnerability','Exploit'))`); params.push('%CVE-%'); }

    const where = conditions.length ? `WHERE ${conditions.join(' AND ')}` : '';
    const countRow = db.prepare(`SELECT COUNT(*) as count FROM articles ${where}`).get(...params);
    const total = countRow.count;
    articles = db.prepare(`SELECT * FROM articles ${where} ORDER BY published_at DESC LIMIT ? OFFSET ?`).all(...params, PER_PAGE, (page - 1) * PER_PAGE);
    pages = Math.ceil(total / PER_PAGE);
  }

  const filterParams = new URLSearchParams();
  if (q) filterParams.set('q', q);
  if (dateFrom) filterParams.set('dateFrom', dateFrom);
  if (dateTo) filterParams.set('dateTo', dateTo);
  if (sector) filterParams.set('sector', sector);
  if (source) filterParams.set('source', source);
  if (tlp) filterParams.set('tlp', tlp);
  if (highRiskOnly) filterParams.set('highRisk', '1');

  res.render('search', {
    query: q, articles, page, pages, cveLookup: null, usedFTS,
    baseUrl: `/search?${filterParams.toString()}`,
    filters: { dateFrom, dateTo, sector, source, tlp, highRiskOnly },
    allSectors, allSources
  });
});

// Sector page
router.get('/sector/:sector', (req, res) => {
  const sector = req.params.sector;
  const page = getPage(req);
  const total = stmts.sectorCount.get(sector).count;
  const articles = stmts.articlesBySector.all(sector, PER_PAGE, (page - 1) * PER_PAGE);
  const pages = Math.ceil(total / PER_PAGE);
  res.render('sector', { pageTitle: sector, sector, articles, page, pages, baseUrl: `/sector/${encodeURIComponent(sector)}` });
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

// Threat Heatmap page
router.get('/heatmap', (req, res) => {
  res.render('heatmap', { pageTitle: 'Threat Heatmap' });
});

// Vulnerability & Exploit Lookup page
router.get('/vulnerability', (req, res) => {
  res.render('vulnlookup', { pageTitle: 'Vulnerability & Exploit Lookup', query: '' });
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
    subscriber = stmts.getSubscriberByToken.get(hashToken(token));
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
  const subscriber = token ? stmts.getSubscriberByToken.get(hashToken(token)) : null;
  if (!subscriber) return res.status(401).json({ error: 'Invalid token' });
  stmts.insertBookmark.run(subscriber.id, articleId);
  res.json({ ok: true });
});

// Remove bookmark
router.post('/bookmarks/remove', (req, res) => {
  const token = req.body.token;
  const articleId = parseInt(req.body.article_id, 10);
  const subscriber = token ? stmts.getSubscriberByToken.get(hashToken(token)) : null;
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
  res.set('Cache-Control', 'public, max-age=3600');
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
    subscriber = stmts.getSubscriberByToken.get(hashToken(token));
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
  const tokenHash = hashToken(token);
  const verifyTokenHash = hashToken(verifyToken);

  // If SMTP is configured, require verification; otherwise auto-verify
  const verified = smtpConfigured() ? 0 : 1;

  stmts.insertSubscriber.run({ email, newsletter, token: tokenHash, verified, verify_token: verifyTokenHash });
  const subscriber = stmts.getSubscriberByToken.get(tokenHash);

  // Process alert rules from the form
  const types = ['vendor', 'category', 'sector', 'keyword'];
  for (const type of types) {
    const values = req.body[type];
    if (!values) continue;
    const arr = Array.isArray(values) ? values : [values];
    for (const val of arr) {
      if (typeof val !== 'string') continue;
      const v = val.trim().slice(0, 200);
      if (v) stmts.insertAlertRule.run({ subscriber_id: subscriber.id, rule_type: type, rule_value: v });
    }
  }

  // Send verification email
  if (smtpConfigured()) {
    try {
      await sendVerification(email, verifyToken);
      res.redirect(`/alerts?token=${encodeURIComponent(token)}&success=subscribed_verify`);
    } catch (_) {
      res.redirect(`/alerts?token=${encodeURIComponent(token)}&success=subscribed`);
    }
  } else {
    res.redirect(`/alerts?token=${encodeURIComponent(token)}&success=subscribed`);
  }
});

// Add alert rule
router.post('/alerts/add-rule', (req, res) => {
  const token = req.body.token;
  const subscriber = token ? stmts.getSubscriberByToken.get(hashToken(token)) : null;
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
  const subscriber = token ? stmts.getSubscriberByToken.get(hashToken(token)) : null;
  if (!subscriber) return res.redirect('/alerts?error=not_found');

  stmts.deleteAlertRule.run(req.body.rule_id, subscriber.id);
  res.redirect(`/alerts?token=${encodeURIComponent(token)}&success=rule_removed`);
});

// Add webhook
router.post('/alerts/add-webhook', (req, res) => {
  const token = req.body.token;
  const subscriber = token ? stmts.getSubscriberByToken.get(hashToken(token)) : null;
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
  stmts.insertWebhook.run({ subscriber_id: subscriber.id, webhook_type: webhookType, webhook_url: encryptWebhookUrl(webhookUrl) });
  res.redirect(`/alerts?token=${encodeURIComponent(token)}&success=webhook_added`);
});

// Delete webhook
router.post('/alerts/delete-webhook', (req, res) => {
  const token = req.body.token;
  const subscriber = token ? stmts.getSubscriberByToken.get(hashToken(token)) : null;
  if (!subscriber) return res.redirect('/alerts?error=not_found');

  stmts.deleteWebhook.run(req.body.webhook_id, subscriber.id);
  res.redirect(`/alerts?token=${encodeURIComponent(token)}&success=webhook_removed`);
});

// Verify email — GET shows confirmation page (no state change, prevents bot auto-verification)
router.get('/alerts/verify', (req, res) => {
  const verifyToken = req.query.token;
  if (!verifyToken) return res.redirect('/alerts?error=invalid_token');

  const subscriber = stmts.getSubscriberByVerifyToken.get(hashToken(verifyToken));
  if (!subscriber) return res.redirect('/alerts?error=invalid_token');

  res.render('verify', { pageTitle: 'Verify Email', verifyToken });
});

// Verify email — POST performs the actual verification
router.post('/alerts/verify', (req, res) => {
  const verifyToken = req.body.verify_token;
  if (!verifyToken) return res.redirect('/alerts?error=invalid_token');

  const subscriber = stmts.getSubscriberByVerifyToken.get(hashToken(verifyToken));
  if (!subscriber) return res.redirect('/alerts?error=invalid_token');

  stmts.verifySubscriber.run(subscriber.id);
  // Do not expose the management token here — user should use their original management link
  res.redirect('/alerts?success=verified');
});

// Resend verification email
router.post('/alerts/resend-verify', emailLimiter, async (req, res) => {
  const token = req.body.token;
  const subscriber = token ? stmts.getSubscriberByToken.get(hashToken(token)) : null;
  if (!subscriber) return res.redirect('/alerts?error=not_found');

  if (subscriber.verified) {
    return res.redirect(`/alerts?token=${encodeURIComponent(token)}&success=already_verified`);
  }

  const newVerifyToken = generateToken();
  stmts.resendVerification.run({ verify_token: hashToken(newVerifyToken), id: subscriber.id });
  try {
    await sendVerification(subscriber.email, newVerifyToken);
  } catch (err) {
    console.error(`[Alerts] Failed to send verification to ${maskEmail(subscriber.email)}: ${err.message}`);
    return res.redirect(`/alerts?token=${encodeURIComponent(token)}&error=email_failed`);
  }
  res.redirect(`/alerts?token=${encodeURIComponent(token)}&success=verification_sent`);
});

// Unsubscribe (supports both POST and GET for email links)
router.get('/alerts/unsubscribe', (req, res) => {
  const token = req.query.token;
  if (!token) return res.redirect('/alerts');
  const subscriber = stmts.getSubscriberByToken.get(hashToken(token));
  if (subscriber) {
    res.render('unsubscribe', { pageTitle: 'Unsubscribe', subscriber });
  } else {
    res.redirect('/alerts?success=unsubscribed');
  }
});

router.post('/alerts/unsubscribe', (req, res) => {
  const token = req.body.token;
  const subscriber = token ? stmts.getSubscriberByToken.get(hashToken(token)) : null;
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
  res.set('Cache-Control', 'public, max-age=300, stale-while-revalidate=60');
  res.json({ data: stmts.vendorCounts.all() });
});

// GET /api/categories — Category list with counts
router.get('/api/categories', (req, res) => {
  res.set('Cache-Control', 'public, max-age=300, stale-while-revalidate=60');
  res.json({ data: stmts.categoryCounts.all() });
});

// GET /api/sectors — Sector list with counts
router.get('/api/sectors', (req, res) => {
  res.set('Cache-Control', 'public, max-age=300, stale-while-revalidate=60');
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
  res.set('Cache-Control', 'public, max-age=300, stale-while-revalidate=60');
  res.json({ categories, vendors, sources, days: safeDays });
});

// In-memory heatmap cache — keyed by safeDays, 15-min TTL
const heatmapCache = {};
const HEATMAP_TTL = 15 * 60 * 1000;

// GET /api/heatmap — Malware family vs threat actor co-occurrence matrix
router.get('/api/heatmap', (req, res) => {
  const days = parseInt(req.query.days, 10) || 90;
  const safeDays = Math.min(Math.max(days, 1), 365);

  const cached = heatmapCache[safeDays];
  if (cached && (Date.now() - cached.cachedAt) < HEATMAP_TTL) {
    res.set('Cache-Control', 'public, max-age=300, stale-while-revalidate=60');
    return res.json(cached.data);
  }

  const articles = db.prepare(`
    SELECT id, title, summary FROM articles
    WHERE published_at >= datetime('now', '-' || ? || ' days')
  `).all(safeDays);

  const { malware_families, threat_actors } = threatmapConfig;
  const malwareNames = Object.keys(malware_families);
  const actorNames = Object.keys(threat_actors);

  // Build co-occurrence matrix and per-entity article lists
  const matrix = {};            // matrix[malware][actor] = count
  const malwareCounts = {};     // total articles per malware
  const actorCounts = {};       // total articles per actor
  const cellArticles = {};      // cellArticles[malware][actor] = [article ids]

  for (const mw of malwareNames) {
    matrix[mw] = {};
    cellArticles[mw] = {};
    malwareCounts[mw] = 0;
    for (const ta of actorNames) {
      matrix[mw][ta] = 0;
      cellArticles[mw][ta] = [];
    }
  }
  for (const ta of actorNames) actorCounts[ta] = 0;

  for (const article of articles) {
    const text = ((article.title || '') + ' ' + (article.summary || '')).toLowerCase();

    // Detect which malware families are mentioned
    const matchedMalware = [];
    for (const [mw, keywords] of Object.entries(malware_families)) {
      for (const kw of keywords) {
        if (text.includes(kw)) {
          matchedMalware.push(mw);
          break;
        }
      }
    }

    // Detect which threat actors are mentioned
    const matchedActors = [];
    for (const [ta, keywords] of Object.entries(threat_actors)) {
      for (const kw of keywords) {
        if (text.includes(kw)) {
          matchedActors.push(ta);
          break;
        }
      }
    }

    // Update individual counts
    for (const mw of matchedMalware) malwareCounts[mw]++;
    for (const ta of matchedActors) actorCounts[ta]++;

    // Update co-occurrence matrix
    for (const mw of matchedMalware) {
      for (const ta of matchedActors) {
        matrix[mw][ta]++;
        cellArticles[mw][ta].push(article.id);
      }
    }
  }

  // Filter to only rows/columns that have at least 1 co-occurrence
  const activeMalware = malwareNames.filter(mw =>
    actorNames.some(ta => matrix[mw][ta] > 0)
  );
  const activeActors = actorNames.filter(ta =>
    malwareNames.some(mw => matrix[mw][ta] > 0)
  );

  // Also include top entities by article count (even without co-occurrence)
  const topMalware = malwareNames
    .filter(mw => malwareCounts[mw] > 0)
    .sort((a, b) => malwareCounts[b] - malwareCounts[a])
    .slice(0, 30);
  const topActors = actorNames
    .filter(ta => actorCounts[ta] > 0)
    .sort((a, b) => actorCounts[b] - actorCounts[a])
    .slice(0, 30);

  // Merge: show union of active (co-occurring) and top-by-count
  const finalMalware = [...new Set([...activeMalware, ...topMalware])];
  const finalActors = [...new Set([...activeActors, ...topActors])];

  // Build compact matrix for response
  const compactMatrix = [];
  let maxCount = 0;
  for (const mw of finalMalware) {
    for (const ta of finalActors) {
      const count = matrix[mw] && matrix[mw][ta] ? matrix[mw][ta] : 0;
      if (count > maxCount) maxCount = count;
      compactMatrix.push({
        malware: mw,
        actor: ta,
        count: count,
        articles: cellArticles[mw] && cellArticles[mw][ta] ? cellArticles[mw][ta].slice(0, 5) : [],
      });
    }
  }

  const heatmapResult = {
    malware: finalMalware,
    actors: finalActors,
    matrix: compactMatrix,
    malwareCounts: Object.fromEntries(finalMalware.map(mw => [mw, malwareCounts[mw]])),
    actorCounts: Object.fromEntries(finalActors.map(ta => [ta, actorCounts[ta]])),
    maxCount,
    days: safeDays,
    totalArticles: articles.length,
  };
  heatmapCache[safeDays] = { data: heatmapResult, cachedAt: Date.now() };
  res.set('Cache-Control', 'public, max-age=300, stale-while-revalidate=60');
  res.json(heatmapResult);
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

  // Articles
  const articles = stmts.suggestions.all(like, like)
    .map(a => ({ type: 'article', title: a.title, vendor: a.vendor, category: a.category, link: a.link }));

  // Local entity lookups
  const groups = stmts.suggestGroups.all(like)
    .map(r => ({ type: 'threat-group', title: r.name, link: `/threat-group/${encodeURIComponent(r.name)}` }));

  const software = stmts.suggestSoftware.all(like)
    .map(r => ({ type: 'software', title: r.name, link: `/software/${encodeURIComponent(r.name)}` }));

  const campaigns = stmts.suggestCampaigns.all(like)
    .map(r => ({ type: 'campaign', title: r.name, link: `/campaign/${encodeURIComponent(r.name)}` }));

  // YARA shortcut — only show when we matched an entity (likely a malware/actor name)
  const entityHits = groups.length + software.length + campaigns.length;
  const yara = entityHits > 0
    ? [{ type: 'yara', title: q, link: `/yara-rules?q=${encodeURIComponent(q)}` }]
    : [];

  // Entities first (most specific), then articles, YARA last
  const results = [...groups, ...software, ...campaigns, ...articles.slice(0, 4), ...yara];
  res.json(results.slice(0, 12));
});

// CVE ticker API (JSON) — returns recently published CVEs newest-first
router.get('/api/cves', async (req, res) => {
  try {
    const cves = await getTickerCVEs();
    res.json(cves);
  } catch (_) {
    res.json([]);
  }
});

// Direct CVE lookup API (JSON) — basic NVD only
router.get('/api/cve/:id', async (req, res) => {
  const id = (req.params.id || '').trim();
  if (!CVE_ID_REGEX.test(id)) {
    return res.status(400).json({ error: 'Invalid CVE ID format. Use CVE-YYYY-NNNNN.' });
  }
  try {
    const cve = await lookupCVE(id);
    if (!cve) return res.status(404).json({ error: 'CVE not found in NVD.' });
    res.json({ data: cve });
  } catch (err) {
    res.status(502).json({ error: 'Failed to fetch from NVD. Try again later.' });
  }
});

// Full multi-source vulnerability lookup API (JSON)
router.get('/api/vuln/:id', async (req, res) => {
  const id = (req.params.id || '').trim();
  if (!CVE_ID_REGEX.test(id)) {
    return res.status(400).json({ error: 'Invalid CVE ID format. Use CVE-YYYY-NNNNN.' });
  }
  try {
    const result = await fullCVELookup(id);
    if (!result) return res.status(404).json({ error: 'CVE not found across any source.' });
    // Enrich with threat intelligence data
    result.threatIntel = lookupThreatIntel(id);
    res.json({ data: result });
  } catch (err) {
    console.error('Vuln lookup error:', err.message);
    res.status(502).json({ error: 'Failed to fetch vulnerability data. Try again later.' });
  }
});

// Health check (JSON)
router.get('/health', (req, res) => {
  const { count } = stmts.totalCount.get();
  res.json({ status: 'ok', articles: count });
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

// =============================================
// Threat Groups, Software & Campaigns
// =============================================

// Helper: daily article counts for the last N days (fills gaps with 0)
function getDailyCounts(rows) {
  const map = {};
  for (const r of rows) map[r.day] = r.count;
  const result = [];
  for (let i = 89; i >= 0; i--) {
    const d = new Date();
    d.setDate(d.getDate() - i);
    const key = d.toISOString().slice(0, 10);
    result.push({ day: key, count: map[key] || 0 });
  }
  return result;
}

// ── Threat Groups ─────────────────────────────────────────────────────────────

const tgStmts = {
  listAll: db.prepare(`
    SELECT tg.*,
      (SELECT COUNT(*) FROM article_threat_groups atg WHERE atg.threat_group_id = tg.id) as total_count,
      (SELECT COUNT(*) FROM article_threat_groups atg
        JOIN articles a ON a.id = atg.article_id
        WHERE atg.threat_group_id = tg.id AND a.published_at >= datetime('now', '-90 days')
      ) as recent_count
    FROM threat_groups tg
    ORDER BY total_count DESC
  `),
  getByName: db.prepare(`SELECT * FROM threat_groups WHERE name = ?`),
  articleCount90: db.prepare(`
    SELECT COUNT(*) as count FROM article_threat_groups atg
    JOIN articles a ON a.id = atg.article_id
    WHERE atg.threat_group_id = ? AND a.published_at >= datetime('now', '-90 days')
  `),
  articleCountAll: db.prepare(`
    SELECT COUNT(*) as count FROM article_threat_groups atg
    WHERE atg.threat_group_id = ?
  `),
  articles90: db.prepare(`
    SELECT a.* FROM articles a
    JOIN article_threat_groups atg ON atg.article_id = a.id
    WHERE atg.threat_group_id = ? AND a.published_at >= datetime('now', '-90 days')
    ORDER BY a.published_at DESC LIMIT ? OFFSET ?
  `),
  articlesAll: db.prepare(`
    SELECT a.* FROM articles a
    JOIN article_threat_groups atg ON atg.article_id = a.id
    WHERE atg.threat_group_id = ?
    ORDER BY a.published_at DESC LIMIT ? OFFSET ?
  `),
  dailyCounts: db.prepare(`
    SELECT date(a.published_at) as day, COUNT(*) as count
    FROM articles a JOIN article_threat_groups atg ON atg.article_id = a.id
    WHERE atg.threat_group_id = ? AND a.published_at >= datetime('now', '-90 days')
    GROUP BY day ORDER BY day
  `),
};

router.get('/threat-groups', (req, res) => {
  const groups = tgStmts.listAll.all();
  res.render('threatgroups', { pageTitle: 'Threat Groups', groups });
});

router.get('/threat-group/:name', (req, res) => {
  const name = req.params.name;
  const group = tgStmts.getByName.get(name);
  if (!group) return res.status(404).render('threatgroups', { pageTitle: 'Threat Groups', groups: tgStmts.listAll.all() });

  const showAll = req.query.all === '1';
  const page = getPage(req);
  const total = showAll
    ? tgStmts.articleCountAll.get(group.id).count
    : tgStmts.articleCount90.get(group.id).count;
  const articles = showAll
    ? tgStmts.articlesAll.all(group.id, PER_PAGE, (page - 1) * PER_PAGE)
    : tgStmts.articles90.all(group.id, PER_PAGE, (page - 1) * PER_PAGE);
  const pages = Math.ceil(total / PER_PAGE);
  const dailyCounts = getDailyCounts(tgStmts.dailyCounts.all(group.id));

  const aliases = group.aliases ? JSON.parse(group.aliases) : [];
  const targetingSectors = group.targeting_sectors ? (() => { try { return JSON.parse(group.targeting_sectors); } catch (_) { return []; } })() : [];
  const targetingGeographies = group.targeting_geographies ? (() => { try { return JSON.parse(group.targeting_geographies); } catch (_) { return []; } })() : [];

  // Related malware (co-occurring in same articles) for relationship graph
  const relatedMalware = db.prepare(`
    SELECT ms.name, COUNT(DISTINCT ams.article_id) as count
    FROM malware_software ms
    JOIN article_malware_sw ams ON ams.malware_sw_id = ms.id
    WHERE ams.article_id IN (
      SELECT article_id FROM article_threat_groups WHERE threat_group_id = ?
    )
    GROUP BY ms.id ORDER BY count DESC LIMIT 6
  `).all(group.id);

  // Aggregate MITRE ATT&CK techniques observed in articles for this group
  const ttpRows = db.prepare(`
    SELECT a.mitre_techniques FROM articles a
    JOIN article_threat_groups atg ON atg.article_id = a.id
    WHERE atg.threat_group_id = ? AND a.mitre_techniques IS NOT NULL
  `).all(group.id);

  const ttpMap = {};
  for (const row of ttpRows) {
    try {
      const techs = JSON.parse(row.mitre_techniques);
      if (!Array.isArray(techs)) continue;
      for (const t of techs) {
        const key = t.id || t;
        if (!ttpMap[key]) ttpMap[key] = { id: t.id || t, name: t.name || t.id || t, tactic: t.tactic || 'unknown', count: 0 };
        ttpMap[key].count++;
      }
    } catch (_) {}
  }
  // Group by tactic, sorted by count desc within each tactic
  const TACTIC_ORDER = ['reconnaissance','resource-development','initial-access','execution','persistence','privilege-escalation','defense-evasion','credential-access','discovery','lateral-movement','collection','command-and-control','exfiltration','impact'];
  const ttpByTactic = {};
  for (const t of Object.values(ttpMap)) {
    const tactic = t.tactic || 'unknown';
    if (!ttpByTactic[tactic]) ttpByTactic[tactic] = [];
    ttpByTactic[tactic].push(t);
  }
  for (const tactic of Object.keys(ttpByTactic)) {
    ttpByTactic[tactic].sort((a, b) => b.count - a.count);
  }
  const observedTtps = TACTIC_ORDER
    .filter(t => ttpByTactic[t])
    .map(t => ({ tactic: t, techniques: ttpByTactic[t] }));
  if (ttpByTactic['unknown']) observedTtps.push({ tactic: 'unknown', techniques: ttpByTactic['unknown'] });

  res.render('threatgroup', {
    pageTitle: group.name,
    group: { ...group, aliases, targetingSectors, targetingGeographies },
    articles, page, pages, total, showAll, dailyCounts,
    baseUrl: `/threat-group/${encodeURIComponent(name)}`,
    relatedMalware,
    observedTtps,
  });
});

// Analyst: update threat actor profile fields (motivation, confidence, sectors, geographies)
router.post('/api/threat-group/:id/profile', requireAuth('analyst'), (req, res) => {
  const id = parseInt(req.params.id, 10);
  if (isNaN(id)) return res.status(400).json({ error: 'Invalid id' });

  const VALID_MOTIVATIONS = ['espionage', 'financial', 'disruption', 'ip-theft', 'unknown'];
  const VALID_CONFIDENCE  = ['low', 'medium', 'high'];

  const { motivation, attribution_confidence, targeting_sectors, targeting_geographies } = req.body || {};

  const updates = [];
  const params  = [];

  if (motivation !== undefined) {
    if (!VALID_MOTIVATIONS.includes(motivation)) return res.status(400).json({ error: 'Invalid motivation' });
    updates.push('motivation = ?'); params.push(motivation);
  }
  if (attribution_confidence !== undefined) {
    if (!VALID_CONFIDENCE.includes(attribution_confidence)) return res.status(400).json({ error: 'Invalid attribution_confidence' });
    updates.push('attribution_confidence = ?'); params.push(attribution_confidence);
  }
  if (targeting_sectors !== undefined) {
    if (!Array.isArray(targeting_sectors)) return res.status(400).json({ error: 'targeting_sectors must be array' });
    updates.push('targeting_sectors = ?'); params.push(JSON.stringify(targeting_sectors));
  }
  if (targeting_geographies !== undefined) {
    if (!Array.isArray(targeting_geographies)) return res.status(400).json({ error: 'targeting_geographies must be array' });
    updates.push('targeting_geographies = ?'); params.push(JSON.stringify(targeting_geographies));
  }

  if (!updates.length) return res.status(400).json({ error: 'No fields to update' });
  params.push(id);
  db.prepare(`UPDATE threat_groups SET ${updates.join(', ')} WHERE id = ?`).run(...params);
  res.json({ ok: true });
});

// ── Software & Malware ────────────────────────────────────────────────────────

const swStmts = {
  listAll: db.prepare(`
    SELECT ms.*,
      (SELECT COUNT(*) FROM article_malware_sw amsw WHERE amsw.malware_sw_id = ms.id) as total_count,
      (SELECT COUNT(*) FROM article_malware_sw amsw
        JOIN articles a ON a.id = amsw.article_id
        WHERE amsw.malware_sw_id = ms.id AND a.published_at >= datetime('now', '-90 days')
      ) as recent_count
    FROM malware_software ms
    WHERE ms.is_auto_detected = 0 OR ms.malpedia_uuid IS NOT NULL
    ORDER BY total_count DESC
  `),
  getByName: db.prepare(`SELECT * FROM malware_software WHERE name = ?`),
  articleCount90: db.prepare(`
    SELECT COUNT(*) as count FROM article_malware_sw amsw
    JOIN articles a ON a.id = amsw.article_id
    WHERE amsw.malware_sw_id = ? AND a.published_at >= datetime('now', '-90 days')
  `),
  articleCountAll: db.prepare(`
    SELECT COUNT(*) as count FROM article_malware_sw WHERE malware_sw_id = ?
  `),
  articles90: db.prepare(`
    SELECT a.* FROM articles a
    JOIN article_malware_sw amsw ON amsw.article_id = a.id
    WHERE amsw.malware_sw_id = ? AND a.published_at >= datetime('now', '-90 days')
    ORDER BY a.published_at DESC LIMIT ? OFFSET ?
  `),
  articlesAll: db.prepare(`
    SELECT a.* FROM articles a
    JOIN article_malware_sw amsw ON amsw.article_id = a.id
    WHERE amsw.malware_sw_id = ?
    ORDER BY a.published_at DESC LIMIT ? OFFSET ?
  `),
  dailyCounts: db.prepare(`
    SELECT date(a.published_at) as day, COUNT(*) as count
    FROM articles a JOIN article_malware_sw amsw ON amsw.article_id = a.id
    WHERE amsw.malware_sw_id = ? AND a.published_at >= datetime('now', '-90 days')
    GROUP BY day ORDER BY day
  `),
};

router.get('/software', (req, res) => {
  const software = swStmts.listAll.all();
  res.render('software', { pageTitle: 'Software & Malware', software });
});

router.get('/software/:name', (req, res) => {
  const name = req.params.name;
  const sw = swStmts.getByName.get(name);
  if (!sw) return res.status(404).render('software', { pageTitle: 'Software & Malware', software: swStmts.listAll.all() });

  const showAll = req.query.all === '1';
  const page = getPage(req);
  const total = showAll
    ? swStmts.articleCountAll.get(sw.id).count
    : swStmts.articleCount90.get(sw.id).count;
  const articles = showAll
    ? swStmts.articlesAll.all(sw.id, PER_PAGE, (page - 1) * PER_PAGE)
    : swStmts.articles90.all(sw.id, PER_PAGE, (page - 1) * PER_PAGE);
  const pages = Math.ceil(total / PER_PAGE);
  const dailyCounts = getDailyCounts(swStmts.dailyCounts.all(sw.id));

  const aliases = sw.aliases ? JSON.parse(sw.aliases) : [];
  res.render('softwaredetail', {
    pageTitle: sw.name,
    sw: { ...sw, aliases },
    articles, page, pages, total, showAll, dailyCounts,
    baseUrl: `/software/${encodeURIComponent(name)}`,
  });
});

// ── Campaigns ─────────────────────────────────────────────────────────────────

const campStmts = {
  listAll: db.prepare(`
    SELECT c.*,
      (SELECT COUNT(*) FROM article_campaigns ac WHERE ac.campaign_id = c.id) as total_count,
      (SELECT COUNT(*) FROM article_campaigns ac
        JOIN articles a ON a.id = ac.article_id
        WHERE ac.campaign_id = c.id AND a.published_at >= datetime('now', '-90 days')
      ) as recent_count
    FROM campaigns c
    ORDER BY total_count DESC
  `),
  getByName: db.prepare(`SELECT * FROM campaigns WHERE name = ?`),
  articleCount90: db.prepare(`
    SELECT COUNT(*) as count FROM article_campaigns ac
    JOIN articles a ON a.id = ac.article_id
    WHERE ac.campaign_id = ? AND a.published_at >= datetime('now', '-90 days')
  `),
  articleCountAll: db.prepare(`
    SELECT COUNT(*) as count FROM article_campaigns WHERE campaign_id = ?
  `),
  articles90: db.prepare(`
    SELECT a.* FROM articles a
    JOIN article_campaigns ac ON ac.article_id = a.id
    WHERE ac.campaign_id = ? AND a.published_at >= datetime('now', '-90 days')
    ORDER BY a.published_at DESC LIMIT ? OFFSET ?
  `),
  articlesAll: db.prepare(`
    SELECT a.* FROM articles a
    JOIN article_campaigns ac ON ac.article_id = a.id
    WHERE ac.campaign_id = ?
    ORDER BY a.published_at DESC LIMIT ? OFFSET ?
  `),
  dailyCounts: db.prepare(`
    SELECT date(a.published_at) as day, COUNT(*) as count
    FROM articles a JOIN article_campaigns ac ON ac.article_id = a.id
    WHERE ac.campaign_id = ? AND a.published_at >= datetime('now', '-90 days')
    GROUP BY day ORDER BY day
  `),
};

router.get('/campaigns', (req, res) => {
  const campaigns = campStmts.listAll.all();
  res.render('campaigns', { pageTitle: 'Campaigns', campaigns });
});

router.get('/campaign/:name', (req, res) => {
  const name = req.params.name;
  const campaign = campStmts.getByName.get(name);
  if (!campaign) return res.status(404).render('campaigns', { pageTitle: 'Campaigns', campaigns: campStmts.listAll.all() });

  const showAll = req.query.all === '1';
  const page = getPage(req);
  const total = showAll
    ? campStmts.articleCountAll.get(campaign.id).count
    : campStmts.articleCount90.get(campaign.id).count;
  const articles = showAll
    ? campStmts.articlesAll.all(campaign.id, PER_PAGE, (page - 1) * PER_PAGE)
    : campStmts.articles90.all(campaign.id, PER_PAGE, (page - 1) * PER_PAGE);
  const pages = Math.ceil(total / PER_PAGE);
  const dailyCounts = getDailyCounts(campStmts.dailyCounts.all(campaign.id));

  const aliases = campaign.aliases ? JSON.parse(campaign.aliases) : [];
  const associated = campaign.associated_groups ? JSON.parse(campaign.associated_groups) : [];
  res.render('campaign', {
    pageTitle: campaign.name,
    campaign: { ...campaign, aliases, associated_groups: associated },
    articles, page, pages, total, showAll, dailyCounts,
    baseUrl: `/campaign/${encodeURIComponent(name)}`,
  });
});

// ── Entity JSON APIs ──────────────────────────────────────────────────────────

router.get('/api/threat-groups', (req, res) => {
  res.set('Cache-Control', 'public, max-age=300, stale-while-revalidate=60');
  res.json({ data: tgStmts.listAll.all() });
});

router.get('/api/software', (req, res) => {
  res.set('Cache-Control', 'public, max-age=300, stale-while-revalidate=60');
  res.json({ data: swStmts.listAll.all() });
});

router.get('/api/campaigns', (req, res) => {
  res.set('Cache-Control', 'public, max-age=300, stale-while-revalidate=60');
  res.json({ data: campStmts.listAll.all() });
});

// GET /api/ai-context/:type/:id — AI intelligence brief (Gemini, cached 24h)
router.get('/api/ai-context/:type/:id', async (req, res) => {
  const { type, id } = req.params;
  const entityId = parseInt(id, 10);
  const VALID_TYPES = ['threat-group', 'software', 'campaign'];
  if (!VALID_TYPES.includes(type) || isNaN(entityId) || entityId <= 0) {
    return res.status(400).json({ error: 'Invalid entity type or id' });
  }

  let entity, articles;
  try {
    if (type === 'threat-group') {
      entity = db.prepare(`SELECT * FROM threat_groups WHERE id = ?`).get(entityId);
      articles = db.prepare(`
        SELECT a.title, a.summary FROM articles a
        JOIN article_threat_groups atg ON atg.article_id = a.id
        WHERE atg.threat_group_id = ? ORDER BY a.published_at DESC LIMIT 5
      `).all(entityId);
      if (entity) {
        try { entity = { ...entity, aliases: JSON.parse(entity.aliases || '[]') }; } catch (_) { entity.aliases = []; }
      }
    } else if (type === 'software') {
      entity = db.prepare(`SELECT * FROM malware_software WHERE id = ?`).get(entityId);
      articles = db.prepare(`
        SELECT a.title, a.summary FROM articles a
        JOIN article_malware_sw ams ON ams.article_id = a.id
        WHERE ams.malware_sw_id = ? ORDER BY a.published_at DESC LIMIT 5
      `).all(entityId);
      if (entity) {
        try { entity = { ...entity, aliases: JSON.parse(entity.aliases || '[]') }; } catch (_) { entity.aliases = []; }
      }
    } else {
      entity = db.prepare(`SELECT * FROM campaigns WHERE id = ?`).get(entityId);
      articles = db.prepare(`
        SELECT a.title, a.summary FROM articles a
        JOIN article_campaigns ac ON ac.article_id = a.id
        WHERE ac.campaign_id = ? ORDER BY a.published_at DESC LIMIT 5
      `).all(entityId);
      if (entity) {
        try { entity = { ...entity, aliases: JSON.parse(entity.aliases || '[]') }; } catch (_) { entity.aliases = []; }
        try { entity = { ...entity, associated_groups: JSON.parse(entity.associated_groups || '[]') }; } catch (_) { entity.associated_groups = []; }
      }
    }
  } catch (_) {
    return res.status(500).json({ error: 'Database error' });
  }

  if (!entity) return res.status(404).json({ error: 'Entity not found' });

  try {
    const result = await getAiContext(type, entityId, entity, articles || []);
    res.json(result);
  } catch (err) {
    const msg = err.message || '';
    const status = msg.includes('GEMINI_API_KEY') ? 503
      : (err.status === 429) ? 503 : 503;
    res.status(status).json({
      error: msg.includes('GEMINI_API_KEY')
        ? 'AI context not available — add GEMINI_API_KEY to .env'
        : (err.status === 429)
        ? 'AI context temporarily unavailable (rate limit)'
        : 'AI context generation failed',
      available: false,
    });
  }
});

// =============================================
// Dashboard Page
// =============================================

const dashStmts = {
  articles24h: db.prepare(`SELECT COUNT(*) as count FROM articles WHERE published_at >= datetime('now', '-1 day')`),
  iocArticles24h: db.prepare(`SELECT COUNT(*) as count FROM articles WHERE iocs IS NOT NULL AND published_at >= datetime('now', '-1 day')`),
  threatGroups7d: db.prepare(`
    SELECT COUNT(DISTINCT atg.threat_group_id) as count FROM article_threat_groups atg
    JOIN articles a ON a.id = atg.article_id
    WHERE a.published_at >= datetime('now', '-7 days')
  `),
  topVendors7d: db.prepare(`
    SELECT vendor, COUNT(*) as count FROM articles
    WHERE published_at >= datetime('now', '-7 days') AND vendor IS NOT NULL
    GROUP BY vendor ORDER BY count DESC LIMIT 6
  `),
  activity7d: db.prepare(`
    SELECT DATE(published_at) as day, COUNT(*) as count FROM articles
    WHERE published_at >= datetime('now', '-7 days')
    GROUP BY day ORDER BY day ASC
  `),
  highRiskArticles: db.prepare(`
    SELECT a.* FROM articles a
    WHERE (a.mitre_techniques IS NOT NULL OR a.iocs IS NOT NULL)
    ORDER BY a.published_at DESC LIMIT 15
  `),
  feedHealthSummary: db.prepare(`
    SELECT
      COUNT(*) as total,
      SUM(CASE WHEN last_status = 'ok' THEN 1 ELSE 0 END) as healthy
    FROM feed_health
  `),
  categoryDist: db.prepare(`
    SELECT category, COUNT(*) as count FROM articles
    WHERE category IS NOT NULL AND category != ''
    GROUP BY category ORDER BY count DESC LIMIT 8
  `),
  totalCount: db.prepare(`SELECT COUNT(*) as count FROM articles`),
};

router.get('/dashboard', async (req, res) => {
  const articles24h = dashStmts.articles24h.get().count;
  const iocArticles24h = dashStmts.iocArticles24h.get().count;
  const threatGroups7d = dashStmts.threatGroups7d.get().count;
  const topVendors7d = dashStmts.topVendors7d.all();
  const feedHealth = dashStmts.feedHealthSummary.get();

  // Build 7-day activity array (fill missing days with 0)
  const activityRows = dashStmts.activity7d.all();
  const activityMap = {};
  activityRows.forEach(r => { activityMap[r.day] = r.count; });
  const activity7d = [];
  for (let i = 6; i >= 0; i--) {
    const d = new Date();
    d.setDate(d.getDate() - i);
    const key = d.toISOString().slice(0, 10);
    const label = d.toLocaleDateString('en-US', { month: 'short', day: 'numeric' });
    activity7d.push({ day: key, label, count: activityMap[key] || 0 });
  }

  // Compute risk scores for recent articles and pick top 10 by score
  const candidateArticles = dashStmts.highRiskArticles.all();
  function computeRisk(a) {
    let score = 0;
    const mitre = (() => { try { return JSON.parse(a.mitre_techniques || '[]'); } catch (_) { return []; } })();
    const iocData = (() => { try { return JSON.parse(a.iocs || 'null'); } catch (_) { return null; } })();
    let iocTotal = 0;
    if (iocData) Object.values(iocData).forEach(v => { if (Array.isArray(v)) iocTotal += v.length; });
    if (iocTotal > 0) score += 20;
    score += Math.min(mitre.length * 10, 30);
    if (/CVE-\d{4}-\d+/i.test(a.title || '')) score += 15;
    if (['Ransomware', 'Data Breach', 'Vulnerability', 'Exploit'].includes(a.category)) score += 15;
    return Math.min(score, 100);
  }
  const highRiskArticles = candidateArticles
    .map(a => ({ ...a, riskScore: computeRisk(a) }))
    .filter(a => a.riskScore >= 25)
    .sort((a, b) => b.riskScore - a.riskScore)
    .slice(0, 8);

  // Latest CVEs for dashboard widget
  let latestCves = [];
  try { latestCves = (await getLatestCVEs()).slice(0, 5); } catch (_) {}

  const categoryDist = dashStmts.categoryDist.all();
  const totalCount = dashStmts.totalCount.get().count;
  res.render('dashboard', {
    pageTitle: 'Dashboard',
    articles24h, iocArticles24h, threatGroups7d,
    topVendors7d, activity7d, feedHealth,
    highRiskArticles, latestCves,
    categoryDist, totalCount,
  });
});

// =============================================
// Unified Lookup Page (CVE / IP / Domain / Hash)
// =============================================

const { lookupIP, lookupDomain, lookupHash } = require('../services/threatIntel');
const {
  threatFoxLookup, malwareBazaarHash, malwareBazaarTag,
  urlhausHost, syncSslBlacklist, getRecentSslBlacklist,
  searchSslBlacklist, getSslBlacklistCount, getLastSslSync,
} = require('../services/abusech');

router.get('/lookup', (req, res) => {
  res.render('lookup', { pageTitle: 'IOC Lookup' });
});

// API: IP lookup (AbuseIPDB + ThreatFox in parallel)
router.get('/api/lookup/ip', async (req, res) => {
  const q = (req.query.q || '').trim();
  if (!q) return res.status(400).json({ error: 'IP address required' });
  if (!/^(\d{1,3}\.){3}\d{1,3}$/.test(q) || q.split('.').some(o => parseInt(o, 10) > 255)) return res.status(400).json({ error: 'Invalid IPv4 address' });
  const [abuseResult, tfResult] = await Promise.allSettled([
    lookupIP(q),
    threatFoxLookup(q),
  ]);
  if (abuseResult.status === 'rejected' && tfResult.status === 'rejected') {
    return res.status(502).json({ error: 'Lookup failed' });
  }
  res.json({
    data: abuseResult.status === 'fulfilled' ? abuseResult.value : null,
    threatfox: tfResult.status === 'fulfilled' ? tfResult.value : [],
  });
});

// API: Domain lookup (RDAP + ThreatFox + URLhaus in parallel)
router.get('/api/lookup/domain', async (req, res) => {
  const q = (req.query.q || '').trim().toLowerCase();
  if (!q) return res.status(400).json({ error: 'Domain required' });
  if (!/^[a-z0-9]([a-z0-9\-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9\-]{0,61}[a-z0-9])?)*\.[a-z]{2,}$/.test(q)) {
    return res.status(400).json({ error: 'Invalid domain format' });
  }
  const [rdapResult, tfResult, uhResult] = await Promise.allSettled([
    lookupDomain(q),
    threatFoxLookup(q),
    urlhausHost(q),
  ]);
  res.json({
    data: rdapResult.status === 'fulfilled' ? rdapResult.value : null,
    threatfox: tfResult.status === 'fulfilled' ? tfResult.value : [],
    urlhaus: uhResult.status === 'fulfilled' ? uhResult.value : null,
  });
});

// API: Hash lookup (VirusTotal + MalwareBazaar in parallel)
router.get('/api/lookup/hash', async (req, res) => {
  const q = (req.query.q || '').trim().toLowerCase();
  if (!q) return res.status(400).json({ error: 'Hash required' });
  if (!/^[a-f0-9]{32}$|^[a-f0-9]{40}$|^[a-f0-9]{64}$/.test(q)) {
    return res.status(400).json({ error: 'Invalid hash (MD5/SHA1/SHA256 expected)' });
  }
  const [vtResult, mbResult] = await Promise.allSettled([
    lookupHash(q),
    malwareBazaarHash(q),
  ]);
  res.json({
    data: vtResult.status === 'fulfilled' ? vtResult.value : null,
    malwarebazaar: mbResult.status === 'fulfilled' ? mbResult.value : null,
  });
});

// =============================================
// YARA Rules (/yara-rules)
// =============================================

router.get('/yara-rules', (req, res) => {
  res.render('yara', { pageTitle: 'YARA Rules' });
});

router.get('/api/yara-rules', async (req, res) => {
  const q = (req.query.q || '').trim().slice(0, 100);
  if (!q) return res.status(400).json({ error: 'Tag or malware name required' });
  try {
    const results = await malwareBazaarTag(q, 20);
    res.json({ results, query: q });
  } catch (err) {
    console.error('[ERROR] YARA lookup:', err);
    res.status(502).json({ error: 'YARA lookup failed' });
  }
});

// =============================================
// SSL Blacklist (/ssl-blacklist)
// =============================================

router.get('/ssl-blacklist', (req, res) => {
  const entries = getRecentSslBlacklist(500);
  const lastSync = getLastSslSync();
  const total = getSslBlacklistCount();
  res.render('sslblacklist', { pageTitle: 'SSL Blacklist', entries, lastSync, total });
});

router.get('/api/ssl-blacklist', (req, res) => {
  const q = (req.query.q || '').trim();
  const results = q ? searchSslBlacklist(q) : getRecentSslBlacklist(200);
  res.json({ results, total: getSslBlacklistCount() });
});

router.post('/api/ssl-blacklist/sync', requireAuth('admin'), async (req, res) => {
  try {
    const count = await syncSslBlacklist();
    res.json({ ok: true, count });
  } catch (err) {
    console.error('[ERROR] SSL blacklist sync:', err);
    res.status(502).json({ ok: false, error: 'SSL blacklist sync failed' });
  }
});

// =============================================
// IOC Bulk Export (CSV / JSON / STIX 2.1)
// =============================================
router.get('/export/iocs', (req, res) => {
  const format = (req.query.format || 'json').toLowerCase();
  const days = parseInt(req.query.days, 10) || 0;

  let rows;
  if (days > 0) {
    rows = db.prepare(`SELECT title, link, source, published_at, iocs FROM articles WHERE iocs IS NOT NULL AND published_at >= datetime('now', '-' || ? || ' days')`).all(days);
  } else {
    rows = db.prepare(`SELECT title, link, source, published_at, iocs FROM articles WHERE iocs IS NOT NULL ORDER BY published_at DESC LIMIT 10000`).all();
  }

  const iocList = [];
  for (const row of rows) {
    let iocData;
    try { iocData = JSON.parse(row.iocs); } catch (_) { continue; }
    const types = ['ips', 'domains', 'urls', 'hashes', 'emails', 'cves'];
    for (const type of types) {
      if (!Array.isArray(iocData[type])) continue;
      for (const value of iocData[type]) {
        iocList.push({ type: type.replace(/s$/, ''), value, source: row.source, article_title: row.title, article_url: row.link, published_at: row.published_at });
      }
    }
  }

  if (format === 'csv') {
    res.setHeader('Content-Type', 'text/csv');
    res.setHeader('Content-Disposition', 'attachment; filename="freeintelhub-iocs.csv"');
    const escCsv = (s) => `"${String(s || '').replace(/"/g, '""')}"`;
    const header = 'type,value,source,article_title,article_url,published_at\n';
    const body = iocList.map(i => [i.type, i.value, i.source, i.article_title, i.article_url, i.published_at].map(escCsv).join(',')).join('\n');
    return res.send(header + body);
  }

  if (format === 'stix') {
    const now = new Date().toISOString();
    function escStix(s) { return String(s).replace(/\\/g, '\\\\').replace(/'/g, "\\'"); }
    const indicators = iocList.map((ioc, idx) => {
      let pattern = '';
      const sv = escStix(ioc.value);
      if (ioc.type === 'ip') pattern = `[ipv4-addr:value = '${sv}']`;
      else if (ioc.type === 'domain') pattern = `[domain-name:value = '${sv}']`;
      else if (ioc.type === 'url') pattern = `[url:value = '${sv}']`;
      else if (ioc.type === 'hash') pattern = `[file:hashes.MD5 = '${sv}']`;
      else if (ioc.type === 'email') pattern = `[email-addr:value = '${sv}']`;
      else if (ioc.type === 'cve') pattern = `[vulnerability:name = '${sv}']`;
      else pattern = `[artifact:payload_bin = '${sv}']`;
      const id = `indicator--${Buffer.from(ioc.value).toString('hex').padEnd(32, '0').slice(0, 8)}-${idx.toString().padStart(4, '0')}-0000-0000-000000000000`;
      return {
        type: 'indicator', spec_version: '2.1', id,
        created: now, modified: now, name: ioc.value, pattern,
        pattern_type: 'stix', valid_from: ioc.published_at || now,
        labels: [ioc.type],
        external_references: [{ source_name: ioc.source, url: ioc.article_url || '' }]
      };
    });
    res.setHeader('Content-Type', 'application/json');
    res.setHeader('Content-Disposition', 'attachment; filename="freeintelhub-iocs.stix.json"');
    return res.json({ type: 'bundle', id: `bundle--fih-${Date.now()}`, spec_version: '2.1', objects: indicators });
  }

  // Default: JSON
  res.setHeader('Content-Type', 'application/json');
  res.setHeader('Content-Disposition', 'attachment; filename="freeintelhub-iocs.json"');
  res.json({ exported_at: new Date().toISOString(), count: iocList.length, iocs: iocList });
});

// =============================================
// MITRE ATT&CK Navigator Export
// =============================================
router.get('/export/mitre-layer', (req, res) => {
  const days = parseInt(req.query.days, 10) || 30;
  const rows = db.prepare(`SELECT mitre_techniques FROM articles WHERE mitre_techniques IS NOT NULL AND published_at >= datetime('now', '-' || ? || ' days')`).all(days);

  const counts = {};
  for (const row of rows) {
    let techs;
    try { techs = JSON.parse(row.mitre_techniques); } catch (_) { continue; }
    if (!Array.isArray(techs)) continue;
    for (const t of techs) {
      const id = typeof t === 'string' ? t : (t && t.id);
      if (id) counts[id] = (counts[id] || 0) + 1;
    }
  }

  const maxCount = Math.max(...Object.values(counts), 1);
  const techniques = Object.entries(counts).map(([techniqueID, count]) => ({
    techniqueID,
    score: Math.round((count / maxCount) * 100),
    color: count > maxCount * 0.7 ? '#ef4444' : count > maxCount * 0.4 ? '#fbbf24' : '#22d3ee',
    comment: `Seen in ${count} article${count !== 1 ? 's' : ''} (last ${days} days)`
  }));

  const layer = {
    name: `FreeIntelHub — ${days}-Day TTP Coverage`,
    versions: { attack: '14', navigator: '4.9', layer: '4.5' },
    domain: 'enterprise-attack',
    description: `Generated by FreeIntelHub on ${new Date().toDateString()}. Darker = more frequent.`,
    techniques,
    gradient: { colors: ['#22d3ee', '#fbbf24', '#ef4444'], minValue: 0, maxValue: 100 },
    legendItems: [], metadata: [], showTacticRowBackground: false
  };

  res.setHeader('Content-Type', 'application/json');
  res.setHeader('Content-Disposition', `attachment; filename="fih-mitre-${days}d.json"`);
  res.json(layer);
});


// =============================================
// CVE Prioritization Dashboard (/cve-priority)
// =============================================
const CISA_KEV_URL = 'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json';
const EPSS_URL = 'https://api.first.org/data/v1/epss';

let kevCache = { data: null, fetchedAt: 0 };
let epssCache = {};

async function fetchKEV() {
  if (kevCache.data && (Date.now() - kevCache.fetchedAt) < 12 * 3600 * 1000) return kevCache.data;
  const https = require('https');
  return new Promise((resolve) => {
    https.get(CISA_KEV_URL, (r) => {
      let d = '';
      r.on('data', c => d += c);
      r.on('end', () => {
        try {
          const parsed = JSON.parse(d);
          const map = {};
          for (const v of (parsed.vulnerabilities || [])) map[v.cveID] = v;
          kevCache = { data: map, fetchedAt: Date.now() };
          resolve(map);
        } catch (_) { resolve({}); }
      });
    }).on('error', () => resolve({}));
  });
}

async function fetchEPSS(cveIds) {
  if (!cveIds.length) return {};
  const uncached = cveIds.filter(id => !epssCache[id]);
  if (uncached.length) {
    // Evict oldest entries if cache is too large
    const cacheKeys = Object.keys(epssCache);
    if (cacheKeys.length > 5000) {
      cacheKeys.slice(0, cacheKeys.length - 4000).forEach(k => delete epssCache[k]);
    }
    const https = require('https');
    const qs = uncached.map(id => `cve=${encodeURIComponent(id)}`).join('&');
    await new Promise((resolve) => {
      https.get(`${EPSS_URL}?${qs}&limit=1000`, (r) => {
        let d = '';
        r.on('data', c => d += c);
        r.on('end', () => {
          try {
            const parsed = JSON.parse(d);
            for (const item of (parsed.data || [])) epssCache[item.cve] = parseFloat(item.epss);
          } catch (_) {}
          resolve();
        });
      }).on('error', () => resolve());
    });
  }
  const result = {};
  for (const id of cveIds) result[id] = epssCache[id] || 0;
  return result;
}

const cveArticleCountStmt = db.prepare(
  `SELECT COUNT(*) as count FROM articles WHERE title LIKE ? OR summary LIKE ?`
);

router.get('/cve-priority', async (req, res) => {
  const days     = parseInt(req.query.days, 10) || 30;
  const minEpss  = parseFloat(req.query.minEpss) || 0;
  const kevOnly  = req.query.kev === '1';
  const pocOnly  = req.query.poc === '1';
  const patchOnly = req.query.patch === '1';
  const zerodayOnly = req.query.zeroday === '1';
  const acFilter = req.query.ac || '';           // 'LOW' | 'HIGH' | ''
  const minArticles = parseInt(req.query.minArticles, 10) || 0;

  let latestCvesRaw = [];
  try { latestCvesRaw = (await getLatestCVEs()).slice(0, 50); } catch (_) {}

  const [kevMap, epssMap] = await Promise.all([
    fetchKEV(),
    fetchEPSS(latestCvesRaw.map(c => c.id).filter(Boolean))
  ]);

  let cves = latestCvesRaw.map(c => {
    const inKev  = !!(kevMap[c.id]);
    const epss   = epssMap[c.id] || 0;
    const hasPatch = !!(c.hasPatch);
    const isZeroDay = inKev && !hasPatch;
    let articleMentions = 0;
    try {
      const pat = `%${c.id}%`;
      articleMentions = cveArticleCountStmt.get(pat, pat).count;
    } catch (_) {}
    return {
      ...c,
      epss,
      inKev,
      kevDetails: kevMap[c.id] || null,
      patchNow: inKev && epss >= 0.5,
      isZeroDay,
      articleMentions,
    };
  });

  // Apply filters
  if (minEpss > 0)      cves = cves.filter(c => c.epss >= minEpss);
  if (kevOnly)          cves = cves.filter(c => c.inKev);
  if (pocOnly)          cves = cves.filter(c => c.hasPoc);
  if (patchOnly)        cves = cves.filter(c => c.hasPatch);
  if (zerodayOnly)      cves = cves.filter(c => c.isZeroDay);
  if (acFilter)         cves = cves.filter(c => (c.attackComplexity || '').toUpperCase() === acFilter.toUpperCase());
  if (minArticles > 0)  cves = cves.filter(c => c.articleMentions >= minArticles);

  // Sort: patchNow pinned at top, then newest published date first
  cves.sort((a, b) => {
    if (b.patchNow !== a.patchNow) return b.patchNow ? 1 : -1;
    return new Date(b.published || 0) - new Date(a.published || 0);
  });

  res.render('cvepriority', {
    pageTitle: 'CVE Priority', cves, days, minEpss, kevOnly,
    pocOnly, patchOnly, zerodayOnly, acFilter, minArticles,
  });
});


// =============================================
// Automated Threat Intelligence Report
// =============================================
router.get('/report/weekly', async (req, res) => {
  const days = parseInt(req.query.days, 10) || 7;

  const totalArticles = db.prepare(`SELECT COUNT(*) as count FROM articles WHERE published_at >= datetime('now', '-' || ? || ' days')`).get(days);
  const topActors = db.prepare(`
    SELECT tg.name, COUNT(atg.article_id) as count FROM threat_groups tg
    JOIN article_threat_groups atg ON atg.threat_group_id = tg.id
    JOIN articles a ON a.id = atg.article_id
    WHERE a.published_at >= datetime('now', '-' || ? || ' days')
    GROUP BY tg.id ORDER BY count DESC LIMIT 5
  `).all(days);
  const topSectors = db.prepare(`SELECT sector, COUNT(*) as count FROM articles WHERE sector IS NOT NULL AND published_at >= datetime('now', '-' || ? || ' days') GROUP BY sector ORDER BY count DESC LIMIT 5`).all(days);
  const topCategories = db.prepare(`SELECT category, COUNT(*) as count FROM articles WHERE category IS NOT NULL AND published_at >= datetime('now', '-' || ? || ' days') GROUP BY category ORDER BY count DESC LIMIT 5`).all(days);
  const iocArticleCount = db.prepare(`SELECT COUNT(*) as count FROM articles WHERE iocs IS NOT NULL AND published_at >= datetime('now', '-' || ? || ' days')`).get(days);
  const highRisk = db.prepare(`
    SELECT title, link, source, published_at, mitre_techniques, iocs FROM articles
    WHERE published_at >= datetime('now', '-' || ? || ' days')
    ORDER BY published_at DESC LIMIT 100
  `).all(days).map(a => {
    let mitre = []; try { mitre = JSON.parse(a.mitre_techniques) || []; } catch (_) {}
    let iocTotal = 0; try { const d = JSON.parse(a.iocs); if (d) Object.values(d).forEach(v => { if (Array.isArray(v)) iocTotal += v.length; }); } catch (_) {}
    let score = 0;
    if (iocTotal > 0) score += 20;
    score += Math.min(mitre.length * 10, 30);
    if (/CVE-\d{4}-\d+/i.test(a.title)) score += 15;
    return { ...a, riskScore: Math.min(score, 100) };
  }).filter(a => a.riskScore >= 50).sort((a, b) => b.riskScore - a.riskScore).slice(0, 10);

  let topCves = [];
  try { topCves = (await getLatestCVEs()).slice(0, 5); } catch (_) {}

  res.render('report', {
    pageTitle: `${days}-Day Threat Report`,
    days, totalArticles: totalArticles.count,
    topActors, topSectors, topCategories,
    iocArticleCount: iocArticleCount.count,
    highRisk, topCves,
    generatedAt: new Date().toISOString()
  });
});

// =============================================
// Geographic Threat Map (/geomap)
// =============================================
router.get('/geomap', (req, res) => {
  const days = parseInt(req.query.days, 10) || 30;
  const countryData = db.prepare(`
    SELECT tg.country, COUNT(DISTINCT atg.article_id) as article_count, COUNT(DISTINCT tg.id) as actor_count,
           GROUP_CONCAT(DISTINCT tg.name) as actors
    FROM threat_groups tg
    JOIN article_threat_groups atg ON atg.threat_group_id = tg.id
    JOIN articles a ON a.id = atg.article_id
    WHERE tg.country IS NOT NULL AND tg.country != ''
    AND a.published_at >= datetime('now', '-' || ? || ' days')
    GROUP BY tg.country ORDER BY article_count DESC
  `).all(days);

  res.render('geomap', { pageTitle: 'Geographic Threat Map', countryData, days });
});

// =============================================
// Analyst Notes & Article Tagging
// =============================================
router.post('/api/notes', (req, res) => {
  const { article_id, token, note, tag } = req.body || {};
  if (!article_id || !token) return res.status(400).json({ error: 'article_id and token required' });
  const validTags = ['note', 'confirmed', 'false-positive', 'under-investigation', 'archived'];
  const safeTag = validTags.includes(tag) ? tag : 'note';
  const safeNote = String(note || '').slice(0, 2000);
  const hashedToken = hashToken(token);
  try {
    db.prepare(`INSERT INTO article_notes (article_id, token, note, tag) VALUES (?, ?, ?, ?)`).run(article_id, hashedToken, safeNote, safeTag);
    res.json({ ok: true });
  } catch (err) {
    console.error('[ERROR] notes insert:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

router.get('/api/notes/:article_id', (req, res) => {
  const notes = db.prepare(`SELECT id, note, tag, created_at FROM article_notes WHERE article_id = ? ORDER BY created_at DESC`).all(req.params.article_id);
  res.json({ notes });
});

router.delete('/api/notes/:id', (req, res) => {
  const { token } = req.body || {};
  if (!token) return res.status(400).json({ error: 'token required' });
  const hashedToken = hashToken(token);
  db.prepare(`DELETE FROM article_notes WHERE id = ? AND token = ?`).run(req.params.id, hashedToken);
  res.json({ ok: true });
});

// =============================================
// Custom Feed Sources UI
// =============================================
router.get('/sources/manage', (req, res) => {
  const feeds = db.prepare(`SELECT * FROM custom_feeds ORDER BY created_at DESC`).all();
  res.render('sourcemanage', { pageTitle: 'Manage Custom Sources', feeds });
});

router.post('/sources/manage', requireAuth('analyst'), (req, res) => {
  const { name, url, category } = req.body || {};
  if (!name || !url) return res.status(400).send('Name and URL required');
  try {
    const parsed = new URL(url);
    if (!['http:', 'https:'].includes(parsed.protocol)) throw new Error('Invalid protocol');
    db.prepare(`INSERT OR IGNORE INTO custom_feeds (name, url, category) VALUES (?, ?, ?)`).run(
      String(name).slice(0, 100), url, String(category || '').slice(0, 50)
    );
  } catch (err) {
    console.error('[ERROR] custom feed add:', err);
    return res.status(400).send('Invalid URL provided');
  }
  res.redirect('/sources/manage');
});

router.post('/sources/manage/delete', requireAuth('analyst'), (req, res) => {
  const { id } = req.body || {};
  if (id) db.prepare(`DELETE FROM custom_feeds WHERE id = ?`).run(id);
  res.redirect('/sources/manage');
});

router.post('/sources/manage/toggle', requireAuth('analyst'), (req, res) => {
  const { id } = req.body || {};
  if (id) db.prepare(`UPDATE custom_feeds SET enabled = 1 - enabled WHERE id = ?`).run(id);
  res.redirect('/sources/manage');
});

// =============================================
// Watchlist / Proactive Monitoring
// =============================================
router.get('/watchlist', (req, res) => {
  const token = req.query.token || '';
  if (!token) return res.render('watchlist', { pageTitle: 'Watchlist', items: [], token: '' });
  const items = db.prepare(`SELECT * FROM watchlist WHERE token = ? ORDER BY created_at DESC`).all(hashToken(token));
  res.render('watchlist', { pageTitle: 'Watchlist', items, token });
});

router.post('/api/watchlist', (req, res) => {
  const { token, watch_type, watch_value } = req.body || {};
  if (!token || !watch_type || !watch_value) return res.status(400).json({ error: 'token, watch_type, watch_value required' });
  const validTypes = ['actor', 'malware', 'campaign', 'cve', 'keyword', 'ip'];
  if (!validTypes.includes(watch_type)) return res.status(400).json({ error: 'Invalid watch_type' });
  try {
    db.prepare(`INSERT OR IGNORE INTO watchlist (token, watch_type, watch_value) VALUES (?, ?, ?)`).run(hashToken(token), watch_type, String(watch_value).slice(0, 200));
    res.json({ ok: true });
  } catch (err) {
    console.error('[ERROR] watchlist insert:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

router.delete('/api/watchlist/:id', (req, res) => {
  const { token } = req.body || {};
  if (!token) return res.status(400).json({ error: 'token required' });
  db.prepare(`DELETE FROM watchlist WHERE id = ? AND token = ?`).run(req.params.id, hashToken(token));
  res.json({ ok: true });
});

// =============================================
// Paste Site Monitoring (/pastes)
// =============================================
router.get('/pastes', (req, res) => {
  const hits = db.prepare(`SELECT * FROM paste_hits ORDER BY found_at DESC LIMIT 100`).all();
  res.render('pastes', { pageTitle: 'Paste Monitoring', hits });
});

router.post('/api/pastes/scan', requireAuth('analyst'), async (req, res) => {
  const keywords = db.prepare(`SELECT DISTINCT rule_value FROM alert_rules WHERE rule_type = 'keyword' LIMIT 10`).all().map(r => r.rule_value);
  if (!keywords.length) return res.json({ found: 0, message: 'No keywords configured in alert rules' });

  const https = require('https');
  let totalFound = 0;

  for (const keyword of keywords.slice(0, 3)) {
    await new Promise((resolve) => {
      https.get(`https://psbdmp.ws/api/v3/search/${encodeURIComponent(keyword)}`, { headers: { 'User-Agent': 'FreeIntelHub/1.0' } }, (r) => {
        let d = '';
        r.on('data', c => d += c);
        r.on('end', () => {
          try {
            const parsed = JSON.parse(d);
            const items = Array.isArray(parsed) ? parsed : (parsed.data || parsed.items || []);
            for (const item of items.slice(0, 10)) {
              const pasteId = String(item.id || item.key || Math.random());
              try {
                db.prepare(`INSERT OR IGNORE INTO paste_hits (paste_id, title, content_snippet, source, keyword, full_url) VALUES (?, ?, ?, ?, ?, ?)`).run(
                  pasteId,
                  String(item.title || keyword + ' match').slice(0, 200),
                  String(item.text || item.content || '').slice(0, 500),
                  'psbdmp', keyword,
                  item.url || `https://psbdmp.ws/dump/${pasteId}`
                );
                totalFound++;
              } catch (_) {}
            }
          } catch (_) {}
          resolve();
        });
      }).on('error', () => resolve());
    });
  }

  res.json({ found: totalFound, keywords: keywords.slice(0, 3) });
});

// =============================================
// API Key Management
// =============================================

router.get('/api-keys', (req, res) => {
  const token = req.query.token || '';
  let keys = [];
  if (token) {
    const sub = db.prepare(`SELECT id FROM subscribers WHERE token = ?`).get(hashToken(token));
    if (sub) keys = db.prepare(`SELECT id, name, key_prefix, requests_today, created_at FROM api_keys WHERE subscriber_id = ?`).all(sub.id);
  }
  res.render('apikeys', { pageTitle: 'API Keys', keys, token });
});

router.post('/api-keys', (req, res) => {
  const { token, name } = req.body || {};
  if (!token || !name) return res.status(400).send('Token and name required');
  const sub = db.prepare(`SELECT id FROM subscribers WHERE token = ?`).get(hashToken(token));
  if (!sub) return res.status(403).send('Invalid subscriber token');
  const rawKey = 'fih_' + crypto.randomBytes(24).toString('hex');
  const keyHash = crypto.createHash('sha256').update(rawKey).digest('hex');
  const keyPrefix = rawKey.slice(0, 12) + '...';
  db.prepare(`INSERT INTO api_keys (name, key_hash, key_prefix, subscriber_id) VALUES (?, ?, ?, ?)`).run(String(name).slice(0, 50), keyHash, keyPrefix, sub.id);
  res.render('apikeys', {
    pageTitle: 'API Keys', keys: [], token,
    newKey: rawKey, message: 'Save this key — it will not be shown again.'
  });
});

router.post('/api-keys/delete', (req, res) => {
  const { token, id } = req.body || {};
  if (!token || !id) return res.redirect('/api-keys');
  const sub = db.prepare(`SELECT id FROM subscribers WHERE token = ?`).get(hashToken(token));
  if (sub) db.prepare(`DELETE FROM api_keys WHERE id = ? AND subscriber_id = ?`).run(id, sub.id);
  res.redirect(`/api-keys?token=${encodeURIComponent(token)}`);
});

// API key middleware for /api routes (optional — checked if X-API-Key header present)
function checkApiKey(req, res, next) {
  const keyHeader = req.headers['x-api-key'];
  if (!keyHeader) return next(); // Allow browser access without key
  const keyHash = crypto.createHash('sha256').update(keyHeader).digest('hex');
  const apiKey = stmts.apiKeyByHash.get(keyHash);
  if (!apiKey) return res.status(401).json({ error: 'Invalid API key' });

  // Rate limit: 1000 req/day per key
  const today = new Date().toISOString().slice(0, 10);
  if (apiKey.last_reset !== today) {
    stmts.apiKeyResetCount.run(today, apiKey.id);
  } else if (apiKey.requests_today >= 1000) {
    return res.status(429).json({ error: 'API key rate limit exceeded (1000/day)' });
  } else {
    stmts.apiKeyIncrCount.run(apiKey.id);
  }
  next();
}

// =============================================
// User Authentication & RBAC
// =============================================
const bcrypt = (() => { try { return require('bcrypt'); } catch (_) { return null; } })();

function requireAuth(role) {
  return (req, res, next) => {
    if (!req.session) return res.status(503).json({ error: 'Authentication not configured' });
    const user = req.session.user;
    if (!user) return res.redirect('/login?next=' + encodeURIComponent(req.path));
    const roles = ['viewer', 'analyst', 'admin'];
    if (roles.indexOf(user.role) < roles.indexOf(role || 'viewer')) {
      return res.status(403).render('error', { message: 'Access denied', pageTitle: 'Forbidden' });
    }
    next();
  };
}

// Login-specific rate limiter — stricter than global (VULN-16)
const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 10,
  standardHeaders: true,
  legacyHeaders: false,
  message: 'Too many login attempts, try again later',
});

router.get('/login', (req, res) => {
  if (!bcrypt) return res.send('<p>Auth not available. Run: npm install express-session bcrypt</p>');
  const rawNext = req.query.next || '/dashboard';
  const safeNext = (typeof rawNext === 'string' && rawNext.startsWith('/') && !rawNext.startsWith('//')) ? rawNext : '/dashboard';
  res.render('login', { pageTitle: 'Login', error: null, next: safeNext });
});

router.post('/login', loginLimiter, async (req, res) => {
  if (!bcrypt) return res.redirect('/');
  const { username, password, next } = req.body || {};
  const safeNext = (typeof next === 'string' && next.startsWith('/') && !next.startsWith('//')) ? next : '/dashboard';
  const user = db.prepare(`SELECT * FROM users WHERE username = ?`).get(username);
  if (!user || !(await bcrypt.compare(password, user.password_hash))) {
    return res.render('login', { pageTitle: 'Login', error: 'Invalid username or password', next: safeNext });
  }
  db.prepare(`UPDATE users SET last_login = datetime('now') WHERE id = ?`).run(user.id);
  req.session.user = { id: user.id, username: user.username, role: user.role };
  res.redirect(safeNext);
});

router.post('/logout', (req, res) => {
  if (req.session) req.session.destroy(() => {});
  res.redirect('/');
});

router.get('/admin', requireAuth('admin'), (req, res) => {
  const users = db.prepare(`SELECT id, username, role, created_at, last_login FROM users`).all();
  const customFeeds = db.prepare(`SELECT * FROM custom_feeds ORDER BY created_at DESC`).all();
  const apiKeyCount = db.prepare(`SELECT COUNT(*) as count FROM api_keys`).get();
  res.render('admin', { pageTitle: 'Admin Panel', users, customFeeds, apiKeyCount: apiKeyCount.count, currentUser: req.session && req.session.user });
});

router.post('/admin/users', requireAuth('admin'), async (req, res) => {
  if (!bcrypt) return res.redirect('/admin');
  const { username, password, role } = req.body || {};
  const validRoles = ['viewer', 'analyst', 'admin'];
  const safeRole = validRoles.includes(role) ? role : 'viewer';
  if (!username || !password) return res.redirect('/admin');
  if (password.length < 12) return res.status(400).json({ error: 'Password must be at least 12 characters' });
  const hash = await bcrypt.hash(password, 10);
  try {
    db.prepare(`INSERT OR IGNORE INTO users (username, password_hash, role) VALUES (?, ?, ?)`).run(String(username).slice(0, 50), hash, safeRole);
  } catch (_) {}
  res.redirect('/admin');
});

router.post('/admin/users/delete', requireAuth('admin'), (req, res) => {
  const { id } = req.body || {};
  const currentUser = req.session && req.session.user;
  if (id && currentUser && String(id) !== String(currentUser.id)) {
    db.prepare(`DELETE FROM users WHERE id = ?`).run(id);
  }
  res.redirect('/admin');
});

// =============================================
// Malpedia Enrichment (admin routes)
// =============================================

router.post('/admin/sync-malpedia', requireAuth('admin'), async (req, res) => {
  try {
    const { syncMalpedia } = require('../services/malpedia');
    const result = await syncMalpedia();
    res.json({ ok: true, ...result });
  } catch (err) {
    console.error('[Malpedia] Sync failed:', err);
    res.status(502).json({ ok: false, error: 'Malpedia sync failed' });
  }
});

router.get('/admin/malpedia-status', requireAuth('admin'), (req, res) => {
  const { getLastSync } = require('../services/malpedia');
  res.json(getLastSync() || {});
});

// =============================================
// Case Management (/cases)
// =============================================

router.get('/cases', (req, res) => {
  const status = req.query.status || '';
  const validStatuses = ['open', 'in-progress', 'closed', 'false-positive'];
  const cases = (status && validStatuses.includes(status))
    ? db.prepare(`SELECT c.*, COUNT(ca.article_id) as article_count FROM cases c LEFT JOIN case_articles ca ON ca.case_id = c.id WHERE c.status = ? GROUP BY c.id ORDER BY c.updated_at DESC`).all(status)
    : db.prepare(`SELECT c.*, COUNT(ca.article_id) as article_count FROM cases c LEFT JOIN case_articles ca ON ca.case_id = c.id GROUP BY c.id ORDER BY c.updated_at DESC`).all();
  res.render('cases', { pageTitle: 'Cases', cases, statusFilter: status });
});

router.post('/cases', requireAuth('analyst'), (req, res) => {
  const { title, severity, description } = req.body || {};
  if (!title || !title.trim()) return res.redirect('/cases');
  const validSeverities = ['low', 'medium', 'high', 'critical'];
  const safeSeverity = validSeverities.includes(severity) ? severity : 'medium';
  db.prepare(`INSERT INTO cases (title, severity, description) VALUES (?, ?, ?)`).run(
    String(title).trim().slice(0, 200), safeSeverity, description ? String(description).slice(0, 2000) : null
  );
  res.redirect('/cases');
});

router.get('/cases/:id', (req, res) => {
  const caseId = parseInt(req.params.id, 10);
  if (!caseId) return res.redirect('/cases');
  const c = db.prepare(`SELECT * FROM cases WHERE id = ?`).get(caseId);
  if (!c) return res.status(404).render('error', { pageTitle: 'Not Found', message: 'Case not found.' });
  const articles = db.prepare(`
    SELECT a.*, ca.added_at FROM articles a
    JOIN case_articles ca ON ca.article_id = a.id
    WHERE ca.case_id = ?
    ORDER BY ca.added_at DESC
  `).all(caseId);
  const notes = db.prepare(`SELECT * FROM case_notes WHERE case_id = ? ORDER BY created_at ASC`).all(caseId);
  const allCases = db.prepare(`SELECT id, title FROM cases WHERE status IN ('open','in-progress') ORDER BY updated_at DESC LIMIT 30`).all();
  res.render('case', { pageTitle: `Case: ${c.title}`, case: c, articles, notes, allCases, safeHref });
});

router.post('/cases/:id/status', requireAuth('analyst'), (req, res) => {
  const caseId = parseInt(req.params.id, 10);
  const { status } = req.body || {};
  const valid = ['open', 'in-progress', 'closed', 'false-positive'];
  if (!caseId || !valid.includes(status)) return res.redirect('/cases');
  const closedAt = (status === 'closed' || status === 'false-positive') ? `datetime('now')` : 'NULL';
  db.prepare(`UPDATE cases SET status = ?, updated_at = datetime('now'), closed_at = ${closedAt} WHERE id = ?`).run(status, caseId);
  res.redirect(`/cases/${caseId}`);
});

router.post('/cases/:id/notes', requireAuth('analyst'), (req, res) => {
  const caseId = parseInt(req.params.id, 10);
  const { note, author } = req.body || {};
  if (!caseId || !note || !note.trim()) return res.redirect(`/cases/${caseId}`);
  db.prepare(`INSERT INTO case_notes (case_id, author, note) VALUES (?, ?, ?)`).run(
    caseId, String(author || 'analyst').slice(0, 50), String(note).trim().slice(0, 5000)
  );
  db.prepare(`UPDATE cases SET updated_at = datetime('now') WHERE id = ?`).run(caseId);
  res.redirect(`/cases/${caseId}`);
});

// API: list open cases (for "Add to Case" dropdown)
router.get('/api/cases', (req, res) => {
  const cases = db.prepare(`SELECT id, title, severity, status FROM cases WHERE status IN ('open','in-progress') ORDER BY updated_at DESC LIMIT 50`).all();
  res.json(cases);
});

// API: add article to case
router.post('/api/cases/:id/articles', requireAuth('analyst'), (req, res) => {
  const caseId = parseInt(req.params.id, 10);
  const articleId = parseInt((req.body || {}).article_id, 10);
  if (!caseId || !articleId) return res.status(400).json({ error: 'Missing case_id or article_id' });
  const c = db.prepare(`SELECT id FROM cases WHERE id = ?`).get(caseId);
  if (!c) return res.status(404).json({ error: 'Case not found' });
  db.prepare(`INSERT OR IGNORE INTO case_articles (case_id, article_id) VALUES (?, ?)`).run(caseId, articleId);
  db.prepare(`UPDATE cases SET updated_at = datetime('now') WHERE id = ?`).run(caseId);
  res.json({ ok: true });
});

// API: remove article from case
router.delete('/api/cases/:id/articles/:articleId', requireAuth('analyst'), (req, res) => {
  const caseId = parseInt(req.params.id, 10);
  const articleId = parseInt(req.params.articleId, 10);
  db.prepare(`DELETE FROM case_articles WHERE case_id = ? AND article_id = ?`).run(caseId, articleId);
  db.prepare(`UPDATE cases SET updated_at = datetime('now') WHERE id = ?`).run(caseId);
  res.json({ ok: true });
});

// API: delete a case
router.delete('/api/cases/:id', requireAuth('analyst'), (req, res) => {
  const caseId = parseInt(req.params.id, 10);
  if (!caseId) return res.status(400).json({ error: 'Invalid case id' });
  db.prepare(`DELETE FROM cases WHERE id = ?`).run(caseId);
  res.json({ ok: true });
});

// API: update TLP on an article (analyst override)
router.post('/api/articles/:id/tlp', requireAuth('analyst'), (req, res) => {
  const id = parseInt(req.params.id, 10);
  const { tlp } = req.body || {};
  const valid = ['WHITE', 'GREEN', 'AMBER', 'RED'];
  if (!id || !valid.includes(tlp)) return res.status(400).json({ error: 'Invalid TLP' });
  db.prepare(`UPDATE articles SET tlp = ? WHERE id = ?`).run(tlp, id);
  res.json({ ok: true });
});

module.exports = router;
