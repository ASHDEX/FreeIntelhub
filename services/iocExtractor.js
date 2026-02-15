/**
 * IOC (Indicator of Compromise) Extractor
 * Extracts IPs, domains, hashes, CVE IDs, URLs, and email addresses from text.
 */

const IOC_PATTERNS = {
  cve: /\bCVE-\d{4}-\d{4,}\b/gi,
  ipv4: /\b(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\b/g,
  md5: /\b[a-fA-F0-9]{32}\b/g,
  sha1: /\b[a-fA-F0-9]{40}\b/g,
  sha256: /\b[a-fA-F0-9]{64}\b/g,
  domain: /\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+(?:com|net|org|io|ru|cn|xyz|top|info|biz|cc|tk|ml|ga|cf|gq|onion|bit)\b/gi,
  url: /https?:\/\/[^\s"'<>]{5,200}/gi,
  email: /\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b/g,
};

// Common false positives to filter out
const FP_DOMAINS = new Set([
  'example.com', 'example.org', 'example.net',
  'google.com', 'twitter.com', 'facebook.com', 'github.com',
  'linkedin.com', 'youtube.com', 'reddit.com',
  'microsoft.com', 'apple.com', 'amazon.com',
  't.co', 'bit.ly', 'goo.gl',
  'w3.org', 'schema.org', 'wordpress.com', 'blogger.com',
]);

const FP_IPS = new Set([
  '0.0.0.0', '127.0.0.1', '255.255.255.255',
  '192.168.0.1', '192.168.1.1', '10.0.0.1',
]);

function unique(arr) {
  return [...new Set(arr)];
}

/**
 * Extract all IOCs from text.
 * Returns an object with arrays of each IOC type.
 */
function extractIOCs(text) {
  if (!text) return null;

  const cves = unique((text.match(IOC_PATTERNS.cve) || []).map(s => s.toUpperCase()));
  const ipv4 = unique((text.match(IOC_PATTERNS.ipv4) || []).filter(ip => !FP_IPS.has(ip)));
  const md5 = unique(text.match(IOC_PATTERNS.md5) || []);
  const sha1 = unique(text.match(IOC_PATTERNS.sha1) || []);
  const sha256 = unique(text.match(IOC_PATTERNS.sha256) || []);
  const domains = unique((text.match(IOC_PATTERNS.domain) || [])
    .map(d => d.toLowerCase())
    .filter(d => !FP_DOMAINS.has(d)));
  const urls = unique(text.match(IOC_PATTERNS.url) || []);
  const emails = unique(text.match(IOC_PATTERNS.email) || []);

  // Remove sha1 values that are substrings of sha256
  const cleanSha1 = sha1.filter(h => !sha256.some(s => s.includes(h)));
  // Remove md5 values that are substrings of sha1 or sha256
  const cleanMd5 = md5.filter(h =>
    !sha1.some(s => s.includes(h)) && !sha256.some(s => s.includes(h))
  );

  const result = {};
  if (cves.length) result.cves = cves;
  if (ipv4.length) result.ipv4 = ipv4;
  if (cleanMd5.length) result.md5 = cleanMd5;
  if (cleanSha1.length) result.sha1 = cleanSha1;
  if (sha256.length) result.sha256 = sha256;
  if (domains.length) result.domains = domains;
  if (urls.length) result.urls = urls;
  if (emails.length) result.emails = emails;

  return Object.keys(result).length > 0 ? result : null;
}

module.exports = { extractIOCs };
