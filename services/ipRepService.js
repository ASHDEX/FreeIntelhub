'use strict';

const https = require('https');
const http = require('http');
const dns = require('dns').promises;

// Parse raw query into { host, type, originalUrl }
function parseQuery(raw) {
  const q = raw.trim();
  // Strip URL to hostname
  if (/^https?:\/\//i.test(q)) {
    try {
      const u = new URL(q);
      return { host: u.hostname, type: 'url', originalUrl: q };
    } catch (_) {}
  }
  // IPv4
  if (/^(?:\d{1,3}\.){3}\d{1,3}$/.test(q)) return { host: q, type: 'ip' };
  // IPv6 (simple check)
  if (/^[0-9a-fA-F:]+:[0-9a-fA-F:]+$/.test(q)) return { host: q, type: 'ip' };
  // Domain
  return { host: q, type: 'domain' };
}

// Minimal HTTP/HTTPS fetcher — only calls fixed, hardcoded external URLs
function fetchJSON(url, opts = {}) {
  return new Promise((resolve, reject) => {
    const mod = url.startsWith('https') ? https : http;
    const { body, ...reqOpts } = opts;
    const req = mod.request(url, { ...reqOpts, timeout: 8000 }, (res) => {
      let data = '';
      res.setEncoding('utf8');
      res.on('data', (chunk) => { data += chunk; });
      res.on('end', () => {
        try { resolve({ status: res.statusCode, body: JSON.parse(data) }); }
        catch (_) { resolve({ status: res.statusCode, body: data }); }
      });
    });
    req.setTimeout(8000, () => { req.destroy(new Error('Timeout')); });
    req.on('error', reject);
    if (body) req.write(body);
    req.end();
  });
}

// ip-api.com — free geolocation, no key needed
async function queryIPGeo(ip) {
  try {
    const fields = 'status,message,country,countryCode,region,regionName,city,zip,lat,lon,timezone,isp,org,as,asname,mobile,proxy,hosting,query';
    const res = await fetchJSON(
      `http://ip-api.com/json/${encodeURIComponent(ip)}?fields=${fields}`
    );
    if (res.body && res.body.status === 'success') return res.body;
    return null;
  } catch (_) {
    return null;
  }
}

// URLHaus (abuse.ch) — free, no key needed
async function queryURLHaus(host) {
  try {
    const body = `host=${encodeURIComponent(host)}`;
    const res = await fetchJSON('https://urlhaus-api.abuse.ch/v1/host/', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
        'Content-Length': Buffer.byteLength(body),
        'User-Agent': 'FreeIntelHub/1.0',
      },
      body,
    });
    if (!res.body || typeof res.body !== 'object') return null;
    if (res.body.query_status === 'no_results') return { found: false };
    if (res.body.query_status === 'is_host' || res.body.query_status === 'is_ip_address') {
      return {
        found: true,
        urlCount: res.body.urls_count || 0,
        blacklists: res.body.blacklists || {},
        urls: (res.body.urls || []).slice(0, 5).map(u => ({
          url: u.url,
          status: u.url_status,
          threat: u.threat,
          dateAdded: u.date_added,
          tags: u.tags || [],
        })),
      };
    }
    return { found: false };
  } catch (_) {
    return null;
  }
}

// AbuseIPDB — requires ABUSEIPDB_KEY env var (optional)
async function queryAbuseIPDB(ip) {
  const apiKey = process.env.ABUSEIPDB_KEY;
  if (!apiKey) return null;
  try {
    const res = await fetchJSON(
      `https://api.abuseipdb.com/api/v2/check?ipAddress=${encodeURIComponent(ip)}&maxAgeInDays=90`,
      {
        method: 'GET',
        headers: {
          'Key': apiKey,
          'Accept': 'application/json',
          'User-Agent': 'FreeIntelHub/1.0',
        },
      }
    );
    if (res.status !== 200 || !res.body || !res.body.data) return null;
    return res.body.data;
  } catch (_) {
    return null;
  }
}

async function lookupReputation(query) {
  const parsed = parseQuery(query);
  const { host, type } = parsed;

  const result = {
    query: host,
    type,
    originalUrl: parsed.originalUrl || null,
    ip: null,
    geo: null,
    urlhaus: null,
    abuseipdb: null,
    riskScore: 0,
    riskLevel: 'unknown',
    riskFactors: [],
    abuseipdbAvailable: !!process.env.ABUSEIPDB_KEY,
  };

  // Resolve domain to IP
  if (type === 'domain' || type === 'url') {
    try {
      const addr = await dns.lookup(host, { family: 4 });
      result.ip = addr.address;
    } catch (_) {
      result.ip = null;
    }
  } else {
    result.ip = host;
  }

  // Run lookups in parallel
  const [geo, urlhaus, abuseipdb] = await Promise.all([
    result.ip ? queryIPGeo(result.ip) : Promise.resolve(null),
    queryURLHaus(host),
    result.ip ? queryAbuseIPDB(result.ip) : Promise.resolve(null),
  ]);

  result.geo = geo;
  result.urlhaus = urlhaus;
  result.abuseipdb = abuseipdb;

  // Calculate risk score
  let score = 0;
  const factors = [];

  if (urlhaus && urlhaus.found) {
    score += 40;
    factors.push({ label: 'Listed in URLHaus malware feed', level: 'high' });
    const bl = urlhaus.blacklists || {};
    if (bl.surbl && bl.surbl !== 'not listed') {
      score += 10;
      factors.push({ label: `SURBL: ${bl.surbl}`, level: 'high' });
    }
    if (bl.spamhaus_dbl && bl.spamhaus_dbl !== 'not listed') {
      score += 10;
      factors.push({ label: `Spamhaus DBL: ${bl.spamhaus_dbl}`, level: 'high' });
    }
    if (urlhaus.urls && urlhaus.urls.some(u => u.status === 'online')) {
      score += 15;
      factors.push({ label: 'Active malware URLs detected', level: 'high' });
    }
  }

  if (abuseipdb) {
    const conf = abuseipdb.abuseConfidenceScore || 0;
    if (conf >= 75) {
      score += 35;
      factors.push({ label: `AbuseIPDB: ${conf}% abuse confidence`, level: 'high' });
    } else if (conf >= 25) {
      score += 20;
      factors.push({ label: `AbuseIPDB: ${conf}% abuse confidence`, level: 'medium' });
    } else if (conf > 0) {
      score += 5;
      factors.push({ label: `AbuseIPDB: ${conf}% abuse confidence`, level: 'low' });
    }
    if (abuseipdb.totalReports > 0) {
      factors.push({
        label: `${abuseipdb.totalReports} total abuse reports`,
        level: abuseipdb.totalReports > 100 ? 'high' : 'medium',
      });
    }
  }

  if (geo) {
    if (geo.proxy) { score += 10; factors.push({ label: 'Proxy / VPN detected', level: 'medium' }); }
    if (geo.hosting) { score += 5; factors.push({ label: 'Datacenter / hosting IP', level: 'low' }); }
    if (geo.mobile) { factors.push({ label: 'Mobile network IP', level: 'info' }); }
  }

  if (factors.length === 0) {
    factors.push({ label: 'No threat indicators found', level: 'clean' });
  }

  score = Math.min(score, 100);
  result.riskScore = score;
  result.riskFactors = factors;

  if (score >= 70) result.riskLevel = 'high';
  else if (score >= 40) result.riskLevel = 'medium';
  else if (score >= 10) result.riskLevel = 'low';
  else result.riskLevel = 'clean';

  return result;
}

module.exports = { lookupReputation };
