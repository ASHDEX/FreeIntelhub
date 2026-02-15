const express = require('express');
const path = require('path');
const rateLimit = require('express-rate-limit');
const routes = require('./routes');
const { fetchAllFeeds } = require('./services/rssFetcher');
const { startNewsletterCron } = require('./services/newsletter');
const { cleanupOldArticles } = require('./services/articleCleanup');

const app = express();
const PORT = process.env.PORT || 3000;
const FETCH_INTERVAL = 15 * 60 * 1000; // 15 minutes
const CLEANUP_INTERVAL = 24 * 60 * 60 * 1000; // 24 hours

// View engine
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

// Body parsing
app.use(express.json());
app.use(express.urlencoded({ extended: false }));

// Static files
app.use(express.static(path.join(__dirname, 'public')));

// Rate limiting
app.use(rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 300,
  standardHeaders: true,
  legacyHeaders: false,
}));

// Routes
app.use('/', routes);

// Start server
app.listen(PORT, '0.0.0.0', () => {
  console.log(`FreeIntelHub running on http://localhost:${PORT}`);

  // Initial fetch after 2s, then every 15 min
  setTimeout(fetchAllFeeds, 2000);
  setInterval(fetchAllFeeds, FETCH_INTERVAL);

  // Start daily newsletter cron
  startNewsletterCron();

  // Article cleanup: run on startup and every 24h
  setTimeout(cleanupOldArticles, 10000);
  setInterval(cleanupOldArticles, CLEANUP_INTERVAL);
});
