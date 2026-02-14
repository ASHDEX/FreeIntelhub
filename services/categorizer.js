const vendors = require('../config/vendors.json');

const CATEGORY_PATTERNS = {
  'CVE':        /\bCVE-\d{4}-\d+\b/i,
  'Zero-Day':   /\bzero[- ]?day\b/i,
  'Ransomware': /\bransomware\b/i,
  'Data Breach':/\b(data breach|data leak|leaked|breach)\b/i,
  'Phishing':   /\bphish(ing)?\b/i,
  'Malware':    /\b(malware|trojan|botnet|worm|spyware)\b/i,
  'Advisory':   /\b(advisory|patch|update|fix)\b/i,
};

function detectVendor(text) {
  const lower = text.toLowerCase();
  for (const [vendor, keywords] of Object.entries(vendors)) {
    for (const kw of keywords) {
      if (lower.includes(kw)) return vendor;
    }
  }
  return null;
}

function detectCategory(text) {
  for (const [category, pattern] of Object.entries(CATEGORY_PATTERNS)) {
    if (pattern.test(text)) return category;
  }
  return 'General';
}

function categorize(title, summary = '') {
  const text = `${title} ${summary}`;
  return {
    vendor: detectVendor(text),
    category: detectCategory(text),
  };
}

module.exports = { categorize, detectVendor, detectCategory };
