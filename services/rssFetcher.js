const crypto = require('crypto');
const RSSParser = require('rss-parser');
const db = require('../db');
const feeds = require('../config/feeds.json');
const { categorize } = require('./categorizer');
const { isNewsArticle } = require('./contentFilter');
const { detectMitreTechniques } = require('./mitreMapper');
const { extractIOCs } = require('./iocExtractor');
const { extractEntities, linkArticle } = require('./entityExtractor');
const { upsertIp } = require('./geoipEnricher');
const { settleWithConcurrency } = require('./concurrency');

const parser = new RSSParser({ timeout: 10000 });
const DEFAULT_FETCH_CONCURRENCY = 8;

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
  INSERT OR IGNORE INTO articles (title, link, summary, source, category, vendor, sector, mitre_techniques, iocs, vendors_all, dedup_hash, published_at)
  VALUES (@title, @link, @summary, @source, @category, @vendor, @sector, @mitre_techniques, @iocs, @vendors_all, @dedup_hash, @published_at)
`);

function generateDedupHash(title) {
  const normalized = title.toLowerCase().replace(/[^a-z0-9 ]/g, '').replace(/\s+/g, ' ').trim();
  return crypto.createHash('sha256').update(normalized).digest('hex').slice(0, 16);
}

const getArticleByLink = db.prepare(`SELECT * FROM articles WHERE link = ?`);
const getCustomFeeds = db.prepare(`
  SELECT name, url, category FROM custom_feeds WHERE enabled = 1 ORDER BY name
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

    const newsItems = items.filter(isNewsArticle);

    const articles = newsItems.map((item) => {
      const rawText = stripHtml(item.contentSnippet || item.content || item.summary || '');
      const summary = makeSafeSummary(rawText);
      const fullText = `${item.title || ''} ${rawText}`;
      const { vendor, vendors_all, category, sector } = categorize(item.title || '', rawText);
      const mitre = detectMitreTechniques(fullText);
      const iocs = extractIOCs(fullText);
      const title = (item.title || 'Untitled').slice(0, 300);
      return {
        title,
        link: item.link || '',
        summary,
        source: feed.name,
        category: feed.category || category,
        vendor,
        sector,
        mitre_techniques: mitre ? JSON.stringify(mitre) : null,
        iocs: iocs ? JSON.stringify(iocs) : null,
        vendors_all: vendors_all ? JSON.stringify(vendors_all) : null,
        dedup_hash: generateDedupHash(title),
        published_at: item.isoDate || item.pubDate || new Date().toISOString(),
      };
    });

    // Insert and track which articles are newly added
    const newlyInserted = [];
    const insert = db.transaction((arts) => {
      for (const article of arts) {
        const result = insertArticle.run(article);
        if (result.changes > 0) {
          const row = getArticleByLink.get(article.link);
          if (row) newlyInserted.push({ row, fullText: `${article.title} ${article.summary || ''}` });
        }
      }
    });
    insert(articles);

    // Extract and link entities for new articles, and enrich IPs with geolocation
    for (const { row, fullText } of newlyInserted) {
      try {
        linkArticle(row.id, extractEntities(fullText));
      } catch (err) {
        console.error(`[Entities] Failed for article ${row.id}: ${err.message}`);
      }

      // Enrich extracted IPs with geolocation data
      if (row.iocs) {
        try {
          const iocs = JSON.parse(row.iocs);
          if (iocs.ipv4 && Array.isArray(iocs.ipv4)) {
            for (const ip of iocs.ipv4) {
              upsertIp(ip, { source: 'rss', article_id: row.id });
            }
          }
        } catch (err) {
          console.error(`[GeoIP] Enrichment failed for article ${row.id}: ${err.message}`);
        }
      }
    }

    upsertHealth.run({ source: feed.name, url: feed.url, status: 'ok', success: 1, fail: 0 });
    const filtered = items.length - newsItems.length;
    console.log(`[RSS] ${feed.name}: ${articles.length} articles (${filtered} non-news filtered, ${newlyInserted.length} new)`);
    return newlyInserted.map(({ row }) => row);
  } catch (err) {
    // Sanitize error message — strip paths and internal details
    const safeMsg = (err.message || 'unknown error').replace(/\/[^\s:]+/g, '[path]').slice(0, 100);
    upsertHealth.run({ source: feed.name, url: feed.url, status: `error: ${safeMsg}`, success: 0, fail: 1 });
    console.error(`[RSS] ${feed.name} failed: ${safeMsg}`);
  }
}

async function fetchAllFeeds() {
  const activeFeeds = getActiveFeeds();
  const concurrency = getFetchConcurrency();
  console.log(`[RSS] Fetching ${activeFeeds.length} feed(s) with concurrency ${concurrency}...`);
  const results = await settleWithConcurrency(activeFeeds, concurrency, fetchFeed);

  // Collect all newly inserted articles across feeds
  const allNew = [];
  for (const r of results) {
    if (r.status === 'fulfilled' && Array.isArray(r.value)) {
      allNew.push(...r.value);
    }
  }

  console.log(`[RSS] Done. ${allNew.length} new article(s) total.`);

  // Trigger alert matching for new articles
  if (allNew.length > 0) {
    try {
      const { processNewArticles } = require('./alertMatcher');
      await processNewArticles(allNew);
    } catch (err) {
      console.error(`[Alerts] Error processing alerts: ${err.message}`);
    }
  }
}

function getFetchConcurrency() {
  const raw = parseInt(process.env.RSS_FETCH_CONCURRENCY, 10);
  if (!Number.isFinite(raw) || raw <= 0) return DEFAULT_FETCH_CONCURRENCY;
  return Math.min(raw, 25);
}

function getActiveFeeds() {
  const merged = [];
  const seen = new Set();
  function add(feed) {
    if (!feed || !feed.name || !feed.url) return;
    const key = `${feed.name}\n${feed.url}`.toLowerCase();
    if (seen.has(key)) return;
    seen.add(key);
    merged.push(feed);
  }
  feeds.forEach(add);
  try {
    getCustomFeeds.all().forEach(add);
  } catch (err) {
    console.error(`[RSS] Failed to load custom feeds: ${err.message}`);
  }
  return merged;
}

module.exports = { fetchAllFeeds, getActiveFeeds, getFetchConcurrency };
