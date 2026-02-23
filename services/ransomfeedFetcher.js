const RSSParser = require('rss-parser');

const parser = new RSSParser({ timeout: 15000, headers: { 'User-Agent': 'FreeIntelHub/1.0' } });

let cache = { items: [], fetchedAt: 0 };
const CACHE_TTL = 10 * 60 * 1000; // 10 minutes

const FEED_URL = 'https://ransomfeed.it/rss-complete.php';

// Extract group name, victim, and country from the HTML description
function parseDescription(html) {
  if (!html) return { group: '', victim: '', country: '' };
  // Pattern: "group called <b>GROUP</b> claims attack for <b>VICTIM</b>...from <b>COUNTRY</b>"
  const groupMatch = html.match(/called\s+<b>([^<]+)<\/b>/i);
  const victimMatch = html.match(/for\s+<b>([^<]+)<\/b>/i);
  const countryMatch = html.match(/from\s+<b>([^<]+)<\/b>/i);
  return {
    group: groupMatch ? groupMatch[1].trim() : '',
    victim: victimMatch ? victimMatch[1].trim() : '',
    country: countryMatch ? countryMatch[1].trim() : '',
  };
}

// Strip HTML tags for plain text
function stripHtml(html) {
  if (!html) return '';
  return html.replace(/<[^>]+>/g, '').trim();
}

async function fetchRansomFeed() {
  const now = Date.now();
  if (cache.items.length > 0 && (now - cache.fetchedAt) < CACHE_TTL) {
    return cache.items;
  }

  try {
    const feed = await parser.parseURL(FEED_URL);
    const items = (feed.items || []).map(item => {
      const parsed = parseDescription(item.content || item['content:encoded'] || item.summary || '');
      return {
        title: item.title || '',
        link: item.link || '',
        guid: item.guid || item.id || '',
        pubDate: item.pubDate || item.isoDate || '',
        description: stripHtml(item.content || item['content:encoded'] || item.summary || ''),
        group: parsed.group,
        victim: parsed.victim || item.title || '',
        country: parsed.country,
      };
    });

    if (items.length > 0) {
      cache = { items, fetchedAt: now };
    }
    return items;
  } catch (err) {
    console.error('RansomFeed fetch error:', err.message);
    return cache.items; // return stale cache on error
  }
}

module.exports = { fetchRansomFeed };
