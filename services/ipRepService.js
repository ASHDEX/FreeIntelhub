'use strict';

const https = require('https');
const http = require('http');
const dns = require('dns').promises;

// ── Input parser ────────────────────────────────────────────────────────────
function parseQuery(raw) {
  const q = raw.trim();
  if (/^https?:\/\//i.test(q)) {
    try { const u = new URL(q); return { host: u.hostname, type: 'url', originalUrl: q }; }
    catch (_) {}
  }
  if (/^(?:\d{1,3}\.){3}\d{1,3}$/.test(q)) return { host: q, type: 'ip' };
  if (/^[0-9a-fA-F:]+:[0-9a-fA-F:]+$/.test(q)) return { host: q, type: 'ip' };
  return { host: q, type: 'domain' };
}

// ── HTTP helper (only calls fixed, hardcoded external URLs) ──────────────────
function request(url, opts = {}) {
  return new Promise((resolve, reject) => {
    const mod = url.startsWith('https') ? https : http;
    const { body, ...reqOpts } = opts;
    const req = mod.request(url, { ...reqOpts, timeout: 9000 }, (res) => {
      const chunks = [];
      res.on('data', c => chunks.push(c));
      res.on('end', () => {
        const text = Buffer.concat(chunks).toString('utf8');
        resolve({ status: res.statusCode, text, headers: res.headers });
      });
    });
    req.setTimeout(9000, () => req.destroy(new Error('Timeout')));
    req.on('error', reject);
    if (body) req.write(body);
    req.end();
  });
}

async function fetchJSON(url, opts = {}) {
  const r = await request(url, opts);
  try { return { status: r.status, body: JSON.parse(r.text) }; }
  catch (_) { return { status: r.status, body: null }; }
}

// ── Geolocation — ip-api.com (free, no key) ─────────────────────────────────
async function queryIPGeo(ip) {
  try {
    const fields = 'status,message,country,countryCode,region,regionName,city,zip,lat,lon,timezone,isp,org,as,asname,mobile,proxy,hosting,query';
    const r = await fetchJSON(`http://ip-api.com/json/${encodeURIComponent(ip)}?fields=${fields}`);
    return (r.body && r.body.status === 'success') ? r.body : null;
  } catch (_) { return null; }
}

// ── URLHaus — abuse.ch (free, no key) ───────────────────────────────────────
async function queryURLHaus(host) {
  try {
    const body = `host=${encodeURIComponent(host)}`;
    const r = await fetchJSON('https://urlhaus-api.abuse.ch/v1/host/', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
        'Content-Length': Buffer.byteLength(body),
        'User-Agent': 'FreeIntelHub/1.0',
      },
      body,
    });
    if (!r.body) return null;
    if (r.body.query_status === 'no_results') return { found: false };
    if (r.body.query_status === 'is_host' || r.body.query_status === 'is_ip_address') {
      return {
        found: true,
        urlCount: r.body.urls_count || 0,
        blacklists: r.body.blacklists || {},
        urls: (r.body.urls || []).slice(0, 8).map(u => ({
          url: u.url, status: u.url_status, threat: u.threat,
          dateAdded: u.date_added, tags: u.tags || [],
        })),
      };
    }
    return { found: false };
  } catch (_) { return null; }
}

// ── AbuseIPDB (optional: ABUSEIPDB_KEY env var) ──────────────────────────────
async function queryAbuseIPDB(ip) {
  const apiKey = process.env.ABUSEIPDB_KEY;
  if (!apiKey) return null;
  try {
    const r = await fetchJSON(
      `https://api.abuseipdb.com/api/v2/check?ipAddress=${encodeURIComponent(ip)}&maxAgeInDays=90`,
      { method: 'GET', headers: { 'Key': apiKey, 'Accept': 'application/json', 'User-Agent': 'FreeIntelHub/1.0' } }
    );
    return (r.status === 200 && r.body && r.body.data) ? r.body.data : null;
  } catch (_) { return null; }
}

// ── RDAP — domain registration info (free, no key) ──────────────────────────
async function queryRDAP(domain) {
  try {
    const r = await fetchJSON(`https://rdap.org/domain/${encodeURIComponent(domain)}`, {
      method: 'GET', headers: { 'Accept': 'application/rdap+json', 'User-Agent': 'FreeIntelHub/1.0' },
    });
    if (!r.body || r.body.errorCode) return null;
    const obj = r.body;

    // Extract creation/expiry dates
    let created = null, expires = null, updated = null;
    for (const ev of (obj.events || [])) {
      if (ev.eventAction === 'registration') created = ev.eventDate;
      if (ev.eventAction === 'expiration') expires = ev.eventDate;
      if (ev.eventAction === 'last changed') updated = ev.eventDate;
    }

    // Registrar
    let registrar = null;
    for (const e of (obj.entities || [])) {
      if ((e.roles || []).includes('registrar')) {
        registrar = (e.vcardArray && e.vcardArray[1]) ? e.vcardArray[1].find(v => v[0] === 'fn')?.[3] : null;
        if (!registrar && e.publicIds) registrar = e.publicIds[0]?.identifier;
        break;
      }
    }

    // Name servers
    const nameservers = (obj.nameservers || []).map(ns => ns.ldhName).filter(Boolean).slice(0, 4);

    return { created, expires, updated, registrar, nameservers, status: obj.status || [] };
  } catch (_) { return null; }
}

// ── crt.sh — certificate transparency (free, no key) ───────────────────────
async function queryCertSH(domain) {
  try {
    const r = await fetchJSON(
      `https://crt.sh/?q=${encodeURIComponent(domain)}&output=json`,
      { method: 'GET', headers: { 'User-Agent': 'FreeIntelHub/1.0' } }
    );
    if (!r.body || !Array.isArray(r.body) || r.body.length === 0) return { found: false };

    // Sort by notBefore descending to get the most recent cert
    const sorted = r.body.sort((a, b) => new Date(b.not_before) - new Date(a.not_before));
    const latest = sorted[0];
    const uniqueIssuers = [...new Set(sorted.map(c => c.issuer_name).filter(Boolean))].slice(0, 3);

    return {
      found: true,
      count: r.body.length,
      latest: {
        commonName: latest.common_name,
        issuer: latest.issuer_name,
        notBefore: latest.not_before,
        notAfter: latest.not_after,
        id: latest.id,
      },
      issuers: uniqueIssuers,
    };
  } catch (_) { return null; }
}

// ── DNS records — built-in Node dns module ───────────────────────────────────
async function queryDNSRecords(domain) {
  const safe = async (fn) => { try { return await fn(); } catch (_) { return null; } };
  const [a, aaaa, mx, ns, txt] = await Promise.all([
    safe(() => dns.resolve4(domain)),
    safe(() => dns.resolve6(domain)),
    safe(() => dns.resolveMx(domain)),
    safe(() => dns.resolveNs(domain)),
    safe(() => dns.resolveTxt(domain)),
  ]);
  return {
    a: (a || []).slice(0, 10),
    aaaa: (aaaa || []).slice(0, 5),
    mx: (mx || []).sort((x, y) => x.priority - y.priority).slice(0, 5),
    ns: (ns || []).slice(0, 6),
    txt: (txt || []).map(r => r.join('')).slice(0, 8),
  };
}

// ── HackerTarget reverse IP (free, rate-limited) ─────────────────────────────
async function queryReverseIP(ip) {
  try {
    const r = await request(`https://api.hackertarget.com/reverseiplookup/?q=${encodeURIComponent(ip)}`, {
      method: 'GET', headers: { 'User-Agent': 'FreeIntelHub/1.0' },
    });
    if (!r.text || r.text.includes('error') || r.text.includes('API count')) return null;
    const hosts = r.text.split('\n').map(h => h.trim()).filter(h => h && !h.startsWith('#'));
    return { count: hosts.length, hosts: hosts.slice(0, 10) };
  } catch (_) { return null; }
}

// ── Risk scoring (0–10 scale) ────────────────────────────────────────────────
function calcRisk(urlhaus, abuseipdb, geo) {
  let score = 0;
  const low = [], warning = [], high = [];

  if (urlhaus && urlhaus.found) {
    score += 4.0; high.push('Listed in URLHaus malware feed');
    const bl = urlhaus.blacklists || {};
    if (bl.surbl && bl.surbl !== 'not listed') { score += 1.0; high.push(`SURBL: ${bl.surbl}`); }
    if (bl.spamhaus_dbl && bl.spamhaus_dbl !== 'not listed') { score += 1.0; high.push(`Spamhaus DBL: ${bl.spamhaus_dbl}`); }
    if (urlhaus.urls && urlhaus.urls.some(u => u.status === 'online')) { score += 1.5; high.push('Active malware URLs online'); }
  }

  if (abuseipdb) {
    const conf = abuseipdb.abuseConfidenceScore || 0;
    if (conf >= 75) { score += 3.5; high.push(`AbuseIPDB: ${conf}% abuse confidence`); }
    else if (conf >= 25) { score += 2.0; warning.push(`AbuseIPDB: ${conf}% abuse confidence`); }
    else if (conf >= 10) { score += 0.5; warning.push(`AbuseIPDB: ${conf}% abuse confidence`); }
    if (abuseipdb.totalReports > 100) warning.push(`${abuseipdb.totalReports} abuse reports`);
    else if (abuseipdb.totalReports > 0) low.push(`${abuseipdb.totalReports} abuse report(s)`);
  }

  if (geo) {
    if (geo.proxy) { score += 1.0; warning.push('Proxy / VPN detected'); }
    if (geo.hosting) { score += 0.5; low.push('Datacenter / hosting IP'); }
    if (geo.mobile) low.push('Mobile network');
  }

  score = Math.min(parseFloat(score.toFixed(2)), 10.0);
  const level = score >= 7 ? 'high' : score >= 4 ? 'medium' : score >= 1 ? 'low' : 'clean';

  return { score, level, low, warning, high };
}

// ── Category inference ───────────────────────────────────────────────────────
function inferCategory(riskData, urlhaus, geo) {
  if (riskData.high.length > 0) return 'Malicious';
  if (riskData.warning.length > 0) return 'Suspicious';
  if (geo && geo.hosting) return 'Hosting Provider';
  if (geo && geo.proxy) return 'Proxy / Anonymizer';
  return 'Uncategorized';
}

// ── Main lookup ──────────────────────────────────────────────────────────────
async function lookupReputation(query) {
  const parsed = parseQuery(query);
  const { host, type } = parsed;

  // DNS resolution for domains
  let ip = type === 'ip' ? host : null;
  let dnsRecords = null;

  if (type === 'domain' || type === 'url') {
    const [dnsRes, dnsRec] = await Promise.all([
      (async () => { try { const a = await dns.lookup(host, { family: 4 }); return a.address; } catch (_) { return null; } })(),
      queryDNSRecords(host),
    ]);
    ip = dnsRes;
    dnsRecords = dnsRec;
  }

  // Parallel external lookups
  const [geo, urlhaus, abuseipdb, rdap, certsh, reverseIP] = await Promise.all([
    ip ? queryIPGeo(ip) : null,
    queryURLHaus(host),
    ip ? queryAbuseIPDB(ip) : null,
    (type === 'domain' || type === 'url') ? queryRDAP(host) : null,
    (type === 'domain' || type === 'url') ? queryCertSH(host) : null,
    ip ? queryReverseIP(ip) : null,
  ]);

  const risk = calcRisk(urlhaus, abuseipdb, geo);
  const category = inferCategory(risk, urlhaus, geo);

  return {
    query: host,
    type,
    originalUrl: parsed.originalUrl || null,
    ip,
    geo,
    urlhaus,
    abuseipdb,
    rdap,
    certsh,
    dnsRecords,
    reverseIP,
    riskScore: risk.score,
    riskLevel: risk.level,
    riskLow: risk.low,
    riskWarning: risk.warning,
    riskHigh: risk.high,
    category,
    abuseipdbAvailable: !!process.env.ABUSEIPDB_KEY,
  };
}

module.exports = { lookupReputation };
