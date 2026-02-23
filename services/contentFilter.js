// Filters out non-news content: ads, events, sponsored posts, webinars, etc.

const JUNK_PATTERNS = [
  /\bsponsored\s*(post|content|article)\b/i,
  /\badvertisement\b/i,
  /\bregister now\b/i,
  /\bupcoming event\b/i,
  /\bfree (trial|demo)\b/i,
  /\brequest a demo\b/i,
  /\bcoupon\b/i,
  /\bdiscount\s*code\b/i,
  /\bgiveaway\b/i,
];

// Titles that are too short or generic to be real news
const MIN_TITLE_LENGTH = 15;

function isNewsArticle(item) {
  const title = item.title || '';
  const content = `${title} ${item.contentSnippet || item.content || item.summary || ''}`;

  // Reject if title is too short/empty
  if (title.trim().length < MIN_TITLE_LENGTH) return false;

  // Reject if matches any junk pattern
  for (const pattern of JUNK_PATTERNS) {
    if (pattern.test(content)) return false;
  }

  return true;
}

module.exports = { isNewsArticle };
