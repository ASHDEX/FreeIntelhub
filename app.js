const express = require('express');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const session = (() => { try { return require('express-session'); } catch (_) { return null; } })();
const routes = require('./routes');
const { fetchAllFeeds } = require('./services/rssFetcher');
const { startNewsletterCron } = require('./services/newsletter');
const { cleanupOldArticles } = require('./services/articleCleanup');
const { cleanupStorage } = require('./services/storageCleanup');
const { optimize: dbOptimize, vacuum: dbVacuum } = require('./services/dbMaintenance');
const cveEnrichment = require('./services/cveEnrichment');
const { seedEntities, backfillEntities } = require('./services/entityExtractor');
const darkweb = require('./services/darkweb');

// Restrict .env file permissions (owner read/write only)
try {
  const envPath = path.join(__dirname, '.env');
  if (fs.existsSync(envPath)) fs.chmodSync(envPath, 0o600);
} catch (_) {}

const app = express();
const PORT = process.env.PORT || 3000;
const BIND_HOST = process.env.BIND_HOST || '127.0.0.1';
const FETCH_INTERVAL = 15 * 60 * 1000; // 15 minutes
const CLEANUP_INTERVAL = 24 * 60 * 60 * 1000; // 24 hours
const DW_SCAN_INTERVAL = 4 * 60 * 60 * 1000;  // 4 hours
const DW_SYNC_INTERVAL = 24 * 60 * 60 * 1000; // 24 hours

// Trust proxy — required when behind a reverse proxy/load balancer (nginx, Cloudflare, etc.)
// Set TRUST_PROXY=1 in production for correct IP-based rate limiting
if (process.env.TRUST_PROXY) {
  const val = parseInt(process.env.TRUST_PROXY, 10);
  app.set('trust proxy', isNaN(val) ? process.env.TRUST_PROXY : val);
}

// HTTPS redirect — enforce TLS in production when FORCE_HTTPS=true
if (process.env.FORCE_HTTPS === 'true') {
  app.use((req, res, next) => {
    if (req.header('x-forwarded-proto') !== 'https') {
      return res.redirect(301, `https://${req.header('host')}${req.url}`);
    }
    next();
  });
}

// Generate a unique nonce per request for CSP
app.use((req, res, next) => {
  res.locals.nonce = crypto.randomBytes(16).toString('base64');
  next();
});

// Expose current path to all views for sidebar active state
app.use((req, res, next) => {
  res.locals.currentPath = req.path;
  next();
});

// Security headers
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'", (req, res) => `'nonce-${res.locals.nonce}'`, "https://cdn.jsdelivr.net", "https://cdn.tailwindcss.com"],
      styleSrc: ["'self'", "'unsafe-hashes'", "https://fonts.googleapis.com"],
      imgSrc: ["'self'", "data:"],
      connectSrc: ["'self'"],
      fontSrc: ["'self'", "https://fonts.gstatic.com"],
      objectSrc: ["'none'"],
      frameAncestors: ["'none'"],
    },
  },
  referrerPolicy: { policy: 'strict-origin-when-cross-origin' },
}));

// View engine
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

// Body parsing with size limits
app.use(express.json({ limit: '50kb' }));
app.use(express.urlencoded({ extended: false, limit: '50kb' }));

// Static files
app.use(express.static(path.join(__dirname, 'public'), {
  maxAge: '1d',
  etag: true,
}));

// CSRF protection: verify Origin/Referer on state-changing requests
const BASE_URL = process.env.BASE_URL || 'http://localhost:3000';
app.use((req, res, next) => {
  if (req.method === 'GET' || req.method === 'HEAD' || req.method === 'OPTIONS') {
    return next();
  }
  const origin = req.headers['origin'] || '';
  const referer = req.headers['referer'] || '';
  const allowed = new URL(BASE_URL).origin;
  const localAllowed = `http://localhost:${PORT}`;
  if (origin) {
    if (origin === allowed || origin === localAllowed) return next();
    return res.status(403).json({ error: 'CSRF check failed: invalid origin' });
  }
  if (referer) {
    try {
      const refOrigin = new URL(referer).origin;
      if (refOrigin === allowed || refOrigin === localAllowed) return next();
    } catch (_) {}
    return res.status(403).json({ error: 'CSRF check failed: invalid referer' });
  }
  // No Origin or Referer on a form-encoded POST — this is the browser CSRF vector.
  // Reject it. JSON/API clients (curl, scripts) should use Content-Type: application/json.
  const contentType = req.headers['content-type'] || '';
  if (contentType.includes('application/x-www-form-urlencoded')) {
    return res.status(403).json({ error: 'CSRF check failed: missing origin' });
  }
  // Non-form requests without Origin/Referer (JSON API clients) — allow
  return next();
});

// Rate limiting
app.use(rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 300,
  standardHeaders: true,
  legacyHeaders: false,
}));

// Session middleware — applied globally before routes (VULN-17)
if (session) {
  if (!process.env.SESSION_SECRET) {
    console.warn('[SECURITY] SESSION_SECRET not set — sessions will not persist across restarts');
  }
  app.use(session({
    secret: process.env.SESSION_SECRET || crypto.randomBytes(32).toString('hex'),
    resave: false,
    saveUninitialized: false,
    cookie: {
      secure: process.env.FORCE_HTTPS === 'true',
      sameSite: 'lax',
      httpOnly: true,
      maxAge: 24 * 3600 * 1000,
    },
  }));
}

// Routes
app.use('/', routes);

// Start server
app.listen(PORT, BIND_HOST, () => {
  console.log(`FreeIntelHub running on http://${BIND_HOST}:${PORT}`);

  // Seed curated entity data and backfill existing articles
  seedEntities();
  setTimeout(backfillEntities, 5000);

  // Initial fetch after 2s, then every 15 min
  setTimeout(fetchAllFeeds, 2000);
  setInterval(fetchAllFeeds, FETCH_INTERVAL);

  // Start daily newsletter cron
  startNewsletterCron();

  // Article cleanup: run on startup and every 24h
  setTimeout(cleanupOldArticles, 10000);
  setInterval(cleanupOldArticles, CLEANUP_INTERVAL);

  // Storage cleanup for unbounded tables: run 12h after start, then daily
  setTimeout(cleanupStorage, 12 * 1000);
  setInterval(cleanupStorage, CLEANUP_INTERVAL);

  // SQLite maintenance: optimize on startup, VACUUM weekly
  setTimeout(dbOptimize, 20 * 1000);
  setInterval(dbVacuum, 7 * CLEANUP_INTERVAL);

  // CVE enrichment: EPSS + CISA KEV. Sync once after 60s, then daily.
  setTimeout(() => cveEnrichment.syncAll(), 60 * 1000);
  setInterval(() => cveEnrichment.syncAll(), CLEANUP_INTERVAL);

  // Dark web monitoring — disabled by default since most hosts (Hostinger
  // included) cannot run a Tor daemon. Set DW_ENABLED=true on a host that has
  // a reachable SOCKS5 Tor proxy.
  if (process.env.DW_ENABLED === 'true') {
    const safe = (label, fn) => async () => {
      try { await fn(); }
      catch (err) { console.warn(`[Darkweb] ${label} failed: ${err.message}`); }
    };
    setTimeout(safe('syncGangList',  darkweb.syncGangList),  15000);
    setTimeout(safe('syncForumList', darkweb.syncForumList), 18000);
    setInterval(safe('syncGangList',  darkweb.syncGangList),  DW_SYNC_INTERVAL);
    setInterval(safe('syncForumList', darkweb.syncForumList), DW_SYNC_INTERVAL);
    setTimeout(safe('scanAll', darkweb.scanAll), 30000);
    setInterval(safe('scanAll', darkweb.scanAll), DW_SCAN_INTERVAL);
  } else {
    console.log('[Darkweb] Disabled (set DW_ENABLED=true to enable)');
  }
});
