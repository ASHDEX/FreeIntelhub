// Filters out non-news content: ads, events, sponsored posts, webinars, etc.

const JUNK_PATTERNS = [
  /\bsponsored\b/i,
  /\badvertis(ement|ing|er)\b/i,
  /\bwebinar\b/i,
  /\bregister now\b/i,
  /\bjoin us\b/i,
  /\bevent\s*(recap|announcement|registration)\b/i,
  /\bupcoming event\b/i,
  /\bwhitepaper\b/i,
  /\bebook\b/i,
  /\bfree (trial|demo|download)\b/i,
  /\brequest a demo\b/i,
  /\bproduct launch\b/i,
  /\bpress release\b/i,
  /\bpartner(ship)? announcement\b/i,
  /\baward(s| winner)\b/i,
  /\bpromotion(al)?\b/i,
  /\bcoupon\b/i,
  /\bdiscount\b/i,
  /\bsale\b/i,
  /\bgiveaway\b/i,
  /\bconference\s*(registration|recap|invite)\b/i,
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
