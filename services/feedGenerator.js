/**
 * RSS/Atom Feed Generator
 * Generates RSS 2.0 XML feeds from article data.
 */

const BASE_URL = process.env.BASE_URL || 'http://localhost:3000';

function escXml(s) {
  if (!s) return '';
  return String(s)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&apos;');
}

/**
 * Generate RSS 2.0 XML from a list of articles.
 * @param {string} title - Feed title
 * @param {string} description - Feed description
 * @param {string} feedUrl - Self-referencing URL of this feed
 * @param {Array} articles - Array of article objects from the database
 * @returns {string} RSS 2.0 XML string
 */
function generateRSS(title, description, feedUrl, articles) {
  const items = articles.map(a => {
    let categories = '';
    if (a.category) categories += `    <category>${escXml(a.category)}</category>\n`;
    if (a.vendor) categories += `    <category>${escXml(a.vendor)}</category>\n`;
    if (a.sector) categories += `    <category>${escXml(a.sector)}</category>\n`;

    // Include MITRE techniques as categories
    if (a.mitre_techniques) {
      try {
        const techniques = JSON.parse(a.mitre_techniques);
        for (const t of techniques) {
          categories += `    <category>${escXml(t.id + ' - ' + t.name)}</category>\n`;
        }
      } catch (_) {}
    }

    return `  <item>
    <title>${escXml(a.title)}</title>
    <link>${escXml(a.link)}</link>
    <guid isPermaLink="true">${escXml(a.link)}</guid>
    <description>${escXml(a.summary || '')}</description>
    <source url="${escXml(a.link)}">${escXml(a.source)}</source>
${categories}    <pubDate>${a.published_at ? new Date(a.published_at).toUTCString() : new Date().toUTCString()}</pubDate>
  </item>`;
  }).join('\n');

  return `<?xml version="1.0" encoding="UTF-8"?>
<rss version="2.0" xmlns:atom="http://www.w3.org/2005/Atom">
<channel>
  <title>${escXml(title)}</title>
  <link>${escXml(BASE_URL)}</link>
  <description>${escXml(description)}</description>
  <language>en-us</language>
  <lastBuildDate>${new Date().toUTCString()}</lastBuildDate>
  <atom:link href="${escXml(feedUrl)}" rel="self" type="application/rss+xml"/>
  <ttl>15</ttl>
${items}
</channel>
</rss>`;
}

module.exports = { generateRSS };
