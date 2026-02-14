const RSSParser = require('rss-parser');
const db = require('../db');
const feeds = require('../config/feeds.json');
const { categorize } = require('./categorizer');
const { isNewsArticle } = require('./contentFilter');

const parser = new RSSParser({ timeout: 10000 });

// DMCA-safe summary: max 2 sentences or 160 chars, whichever is shorter
function makeSafeSummary(text) {
  if (!text) return '';
  // Grab first 2 sentences
  const sentences = text.match(/[^.!?]*[.!?]/g);
  const twoSentences = sentences ? sentences.slice(0, 2).join('').trim() : text;
  // Cap at 160 chars
  if (twoSentences.length <= 160) return twoSentences;
  return twoSentences.slice(0, 157) + '...';
}

const insertArticle = db.prepare(`
  INSERT OR IGNORE INTO articles (title, link, summary, source, category, vendor, published_at)
  VALUES (@title, @link, @summary, @source, @category, @vendor, @published_at)
`);

const upsertHealth = db.prepare(`
  INSERT INTO feed_health (source, url, last_status, last_checked_at, success_count, fail_count)
  VALUES (@source, @url, @status, datetime('now'), @success, @fail)
  ON CONFLICT(source) DO UPDATE SET
    last_status = @status,
    last_checked_at = datetime('now'),
    success_count = CASE WHEN @status = 'ok' THEN feed_health.success_count + 1 ELSE feed_health.success_count END,
    fail_count = CASE WHEN @status != 'ok' THEN feed_health.fail_count + 1 ELSE feed_health.fail_count END
`);

function stripHtml(html) {
  if (!html) return '';
  return html.replace(/<[^>]*>/g, '').replace(/\s+/g, ' ').trim().slice(0, 500);
}

async function fetchFeed(feed) {
  try {
    const data = await parser.parseURL(feed.url);
    const items = data.items || [];

    const insert = db.transaction((articles) => {
      for (const article of articles) {
        insertArticle.run(article);
      }
    });

    const newsItems = items.filter(isNewsArticle);

    const articles = newsItems.map((item) => {
      const rawText = stripHtml(item.contentSnippet || item.content || item.summary || '');
      const summary = makeSafeSummary(rawText);
      const { vendor, category } = categorize(item.title || '', rawText);
      return {
        title: (item.title || 'Untitled').slice(0, 300),
        link: item.link || '',
        summary,
        source: feed.name,
        category,
        vendor,
        published_at: item.isoDate || item.pubDate || new Date().toISOString(),
      };
    });

    insert(articles);
    upsertHealth.run({ source: feed.name, url: feed.url, status: 'ok', success: 1, fail: 0 });
    const filtered = items.length - newsItems.length;
    console.log(`[RSS] ${feed.name}: ${articles.length} articles (${filtered} non-news filtered)`);
  } catch (err) {
    upsertHealth.run({ source: feed.name, url: feed.url, status: `error: ${err.message}`.slice(0, 200), success: 0, fail: 1 });
    console.error(`[RSS] ${feed.name} failed: ${err.message}`);
  }
}

async function fetchAllFeeds() {
  console.log('[RSS] Fetching all feeds...');
  await Promise.allSettled(feeds.map(fetchFeed));
  console.log('[RSS] Done.');
}

module.exports = { fetchAllFeeds };
