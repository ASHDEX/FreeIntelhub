const vendors = require('../config/vendors.json');
const sectors = require('../config/sectors.json');

const CATEGORY_PATTERNS = {
  'Data Breach':              /\b(data breach|data leak|leaked|breach|exposed database)\b/i,
  'Zero-Day':                 /\bzero[- ]?day\b/i,
  'Ransomware':               /\bransomware\b/i,
  'CVE':                      /\bCVE-\d{4}-\d+\b/i,
  'Vulnerability Disclosure':  /\b(vulnerability|vuln|exploit|rce|remote code execution|privilege escalation|buffer overflow|sql injection|xss)\b/i,
  'Advisory':                 /\b(advisory|security patch|patch tuesday|hotfix|security update|security fix)\b/i,
  'TTPs':                     /\b(ttp|tactics|techniques|procedures|mitre att&ck|att&ck|kill chain|lateral movement|command and control|c2)\b/i,
  'Campaigns':                /\b(campaign|threat actor|apt|apt\d+|nation[- ]?state|cyber espionage|operation\s\w+)\b/i,
  'Operational Technology':   /\b(ot security|operational technology|ics|scada|plc|industrial control|hmi|dcs|smart grid)\b/i,
  'Phishing':                 /\bphish(ing)?\b/i,
  'Malware':                  /\b(malware|trojan|botnet|worm|spyware|backdoor|rootkit|infostealer|loader)\b/i,
  'Supply Chain':             /\b(supply chain|dependency confusion|typosquatting|software supply)\b/i,
  'DDoS':                     /\b(ddos|denial of service|dos attack)\b/i,
  'Insider Threat':           /\b(insider threat|insider attack|rogue employee)\b/i,
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

function detectSector(text) {
  const lower = text.toLowerCase();
  for (const [sector, keywords] of Object.entries(sectors)) {
    for (const kw of keywords) {
      if (lower.includes(kw)) return sector;
    }
  }
  return null;
}

function categorize(title, summary = '') {
  const text = `${title} ${summary}`;
  return {
    vendor: detectVendor(text),
    category: detectCategory(text),
    sector: detectSector(text),
  };
}

module.exports = { categorize, detectVendor, detectCategory, detectSector, CATEGORY_PATTERNS };
