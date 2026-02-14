const RSSParser = require('rss-parser');
const db = require('../db');
const feeds = require('../config/feeds.json');
const { categorize } = require('./categorizer');

const parser = new RSSParser({ timeout: 10000 });

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

    const articles = items.map((item) => {
      const summary = stripHtml(item.contentSnippet || item.content || item.summary || '');
      const { vendor, category } = categorize(item.title || '', summary);
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
    console.log(`[RSS] ${feed.name}: ${articles.length} items processed`);
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
