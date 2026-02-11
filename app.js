const express = require('express');
const Parser = require('rss-parser');
const path = require('path');
const NodeCache = require('node-cache');
const rateLimit = require('express-rate-limit');

const app = express();
const parser = new Parser();
const cache = new NodeCache({ stdTTL: 300 });

const vendors = require('./vendors.json');

app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));
app.use(express.static(path.join(__dirname, 'public')));

app.use(rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 300
}));

let articles = [];
let cveTicker = [];

// ----------------- Vendor Alias Detection -----------------
function detectVendors(text) {
  if (!text) return [];
  const found = new Set();
  const content = text.toLowerCase();

  for (const [vendor, aliases] of Object.entries(vendors)) {
    for (const alias of aliases) {
      if (content.includes(alias.toLowerCase())) {
        found.add(vendor.toLowerCase());
        break;
      }
    }
  }

  return Array.from(found);
}

// ----------------- RSS FEEDS -----------------
const FEEDS = [
  "https://www.bleepingcomputer.com/feed/",
  "https://feeds.feedburner.com/TheHackersNews",
  "https://www.darkreading.com/rss.xml",
  "https://www.securityweek.com/feed",
  "https://www.bleepingcomputer.com/tag/security/rss/",
  "https://www.recordedfuture.com/rss",
  "https://www.cisa.gov/cybersecurity-advisories/all.xml"
];

// ----------------- FETCH RSS -----------------
async function fetchFeeds() {
  let all = [];

  for (const url of FEEDS) {
    try {
      const feed = await parser.parseURL(url);
      feed.items.forEach(item => {
        const text = `${item.title || ''} ${item.contentSnippet || ''} ${item.content || ''}`;
        all.push({
          title: item.title || 'No title',
          link: item.link,
          summary: item.contentSnippet || '',
          source: feed.title || url,
          published: item.pubDate || item.isoDate || new Date().toISOString(),
          vendors: detectVendors(text)
        });
      });
    } catch (err) {
      console.error(`RSS Error (${url})`, err.message);
    }
  }

  articles = all.sort((a, b) => new Date(b.published) - new Date(a.published));
  console.log(`[+] RSS updated: ${articles.length} articles`);
}

// ----------------- CACHE WRAPPER -----------------
async function getArticlesCached() {
  const cached = cache.get("articles");
  if (cached) return cached;

  await fetchFeeds();
  cache.set("articles", articles);
  return articles;
}

// ----------------- VENDOR INDEX -----------------
function buildVendorIndex(articles) {
  const map = {};

  for (const article of articles) {
    for (const vendor of article.vendors) {
      if (!map[vendor]) {
        map[vendor] = {
          vendor,
          count: 0,
          latest: new Date(article.published || 0)
        };
      }

      map[vendor].count++;

      const published = new Date(article.published || 0);
      if (published > map[vendor].latest) {
        map[vendor].latest = published;
      }
    }
  }

  return Object.values(map).sort((a, b) => b.latest - a.latest);
}

// ----------------- SEARCH -----------------
function searchArticles(query, articles) {
  const q = query.toLowerCase();

  return articles
    .map(a => {
      let score = 0;
      if (a.title.toLowerCase().includes(q)) score += 3;
      if (a.vendors.includes(q)) score += 5;
      if ((a.summary || '').toLowerCase().includes(q)) score += 1;
      return { ...a, score };
    })
    .filter(a => a.score > 0)
    .sort((a, b) => b.score - a.score);
}

// ----------------- ROUTES -----------------
app.get('/', async (req, res) => {
  const articles = await getArticlesCached();
  const vendors = buildVendorIndex(articles);

  res.render('index', {
    news: articles.slice(0, 30),
    vendors,
    cveTicker
  });
});

app.get('/vendor/:vendor', async (req, res) => {
  const vendor = req.params.vendor.toLowerCase();
  const articles = await getArticlesCached();
  const vendorNews = articles.filter(a => a.vendors.includes(vendor));

  res.render('vendor', {
    vendor,
    news: vendorNews
  });
});

app.get('/search', async (req, res) => {
  const q = req.query.q || '';
  const articles = await getArticlesCached();
  const results = q ? searchArticles(q, articles) : [];

  res.render('search', {
    query: q,
    results
  });
});

// ----------------- CVE TICKER STUB -----------------
setInterval(() => {
  cveTicker = []; // Later: replace with real CVE feed
}, 60 * 60 * 1000);

// ----------------- INIT -----------------
fetchFeeds();
setInterval(fetchFeeds, 10 * 60 * 1000);

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`🔥 FreeIntel Hub running on http://localhost:${PORT}`);
});
