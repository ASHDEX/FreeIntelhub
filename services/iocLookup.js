/**
 * IOC Lookup Service
 * Queries threat intelligence providers using user-supplied API keys.
 * Keys are never stored — they are passed per request and discarded.
 */

const https = require('https');
const http = require('http');
const { URL } = require('url');

const TIMEOUT_MS = 15000;

// --- IOC type detection ---

const IOC_TYPE_PATTERNS = {
  ipv4: /^(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)$/,
  md5: /^[a-fA-F0-9]{32}$/,
  sha1: /^[a-fA-F0-9]{40}$/,
  sha256: /^[a-fA-F0-9]{64}$/,
  domain: /^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$/,
  url: /^https?:\/\/.+/i,
};

function detectIOCType(value) {
  if (IOC_TYPE_PATTERNS.ipv4.test(value)) return 'ip';
  if (IOC_TYPE_PATTERNS.sha256.test(value)) return 'hash';
  if (IOC_TYPE_PATTERNS.sha1.test(value)) return 'hash';
  if (IOC_TYPE_PATTERNS.md5.test(value)) return 'hash';
  if (IOC_TYPE_PATTERNS.url.test(value)) return 'url';
  if (IOC_TYPE_PATTERNS.domain.test(value)) return 'domain';
  return null;
}

// --- HTTP helper ---

function fetchJSON(url, options = {}) {
  return new Promise((resolve, reject) => {
    const parsed = new URL(url);
    const lib = parsed.protocol === 'https:' ? https : http;
    const reqOpts = {
      hostname: parsed.hostname,
      port: parsed.port,
      path: parsed.pathname + parsed.search,
      method: options.method || 'GET',
      headers: {
        'Accept': 'application/json',
        'User-Agent': 'FreeIntelHub/1.0',
        ...options.headers,
      },
      timeout: TIMEOUT_MS,
    };

    const req = lib.request(reqOpts, (res) => {
      let data = '';
      res.on('data', (chunk) => { data += chunk; });
      res.on('end', () => {
        try {
          resolve({ status: res.statusCode, data: JSON.parse(data) });
        } catch (_) {
          resolve({ status: res.statusCode, data: null, raw: data });
        }
      });
    });

    req.on('timeout', () => { req.destroy(); reject(new Error('Request timed out')); });
    req.on('error', reject);

    if (options.body) {
      const bodyStr = typeof options.body === 'string' ? options.body : JSON.stringify(options.body);
      req.setHeader('Content-Type', options.contentType || 'application/json');
      req.setHeader('Content-Length', Buffer.byteLength(bodyStr));
      req.write(bodyStr);
    }
    req.end();
  });
}

// --- Provider: VirusTotal ---

async function queryVirusTotal(apiKey, iocValue, iocType) {
  const typeMap = { ip: 'ip_addresses', domain: 'domains', hash: 'files', url: 'urls' };
  const vtType = typeMap[iocType];
  if (!vtType) return { provider: 'VirusTotal', error: `Unsupported IOC type: ${iocType}` };

  let endpoint;
  if (iocType === 'url') {
    // VT requires base64-encoded URL (no padding)
    const urlId = Buffer.from(iocValue).toString('base64').replace(/=+$/, '');
    endpoint = `https://www.virustotal.com/api/v3/urls/${urlId}`;
  } else {
    endpoint = `https://www.virustotal.com/api/v3/${vtType}/${encodeURIComponent(iocValue)}`;
  }

  try {
    const res = await fetchJSON(endpoint, { headers: { 'x-apikey': apiKey } });
    if (res.status === 401) return { provider: 'VirusTotal', error: 'Invalid API key' };
    if (res.status === 404) return { provider: 'VirusTotal', error: 'Not found' };
    if (res.status === 429) return { provider: 'VirusTotal', error: 'Rate limit exceeded' };
    if (res.status !== 200) return { provider: 'VirusTotal', error: `HTTP ${res.status}` };

    const attrs = res.data && res.data.data && res.data.data.attributes;
    if (!attrs) return { provider: 'VirusTotal', error: 'Unexpected response' };

    const stats = attrs.last_analysis_stats || {};
    const result = {
      provider: 'VirusTotal',
      found: true,
      malicious: stats.malicious || 0,
      suspicious: stats.suspicious || 0,
      harmless: stats.harmless || 0,
      undetected: stats.undetected || 0,
      total: (stats.malicious || 0) + (stats.suspicious || 0) + (stats.harmless || 0) + (stats.undetected || 0),
      reputation: attrs.reputation,
      link: `https://www.virustotal.com/gui/${vtType === 'ip_addresses' ? 'ip-address' : vtType.replace(/_/g, '-').replace(/s$/, '')}/${encodeURIComponent(iocValue)}`,
    };

    if (attrs.as_owner) result.as_owner = attrs.as_owner;
    if (attrs.country) result.country = attrs.country;
    if (attrs.meaningful_name) result.name = attrs.meaningful_name;
    if (attrs.popular_threat_classification) {
      const ptc = attrs.popular_threat_classification;
      if (ptc.suggested_threat_label) result.threat_label = ptc.suggested_threat_label;
    }
    if (attrs.tags && attrs.tags.length) result.tags = attrs.tags.slice(0, 10);
    if (attrs.last_analysis_date) result.last_analysis = new Date(attrs.last_analysis_date * 1000).toISOString();

    return result;
  } catch (err) {
    return { provider: 'VirusTotal', error: err.message };
  }
}

// --- Provider: AbuseIPDB ---

async function queryAbuseIPDB(apiKey, iocValue, iocType) {
  if (iocType !== 'ip') return { provider: 'AbuseIPDB', error: 'Only supports IP lookups' };

  try {
    const endpoint = `https://api.abuseipdb.com/api/v2/check?ipAddress=${encodeURIComponent(iocValue)}&maxAgeInDays=90&verbose=true`;
    const res = await fetchJSON(endpoint, { headers: { 'Key': apiKey } });

    if (res.status === 401) return { provider: 'AbuseIPDB', error: 'Invalid API key' };
    if (res.status === 404) return { provider: 'AbuseIPDB', error: 'Not found' };
    if (res.status === 422) return { provider: 'AbuseIPDB', error: 'Invalid IP address' };
    if (res.status === 429) return { provider: 'AbuseIPDB', error: 'Rate limit exceeded' };
    if (res.status !== 200) return { provider: 'AbuseIPDB', error: `HTTP ${res.status}` };

    const d = res.data && res.data.data;
    if (!d) return { provider: 'AbuseIPDB', error: 'Unexpected response' };

    return {
      provider: 'AbuseIPDB',
      found: true,
      abuse_confidence: d.abuseConfidencePercentage,
      total_reports: d.totalReports,
      country: d.countryCode,
      isp: d.isp,
      domain: d.domain,
      is_tor: d.isTor,
      is_whitelisted: d.isWhitelisted,
      usage_type: d.usageType,
      last_reported: d.lastReportedAt,
      link: `https://www.abuseipdb.com/check/${encodeURIComponent(iocValue)}`,
    };
  } catch (err) {
    return { provider: 'AbuseIPDB', error: err.message };
  }
}

// --- Provider: ThreatFox (abuse.ch) — no key required ---

async function queryThreatFox(apiKey, iocValue, iocType) {
  if (iocType !== 'ip' && iocType !== 'domain' && iocType !== 'hash' && iocType !== 'url') {
    return { provider: 'ThreatFox', error: `Unsupported IOC type: ${iocType}` };
  }

  try {
    const body = JSON.stringify({ query: 'search_ioc', search_term: iocValue });
    const res = await fetchJSON('https://threatfox-api.abuse.ch/api/v1/', {
      method: 'POST',
      body,
    });

    if (res.status !== 200) return { provider: 'ThreatFox', error: `HTTP ${res.status}` };
    if (!res.data) return { provider: 'ThreatFox', error: 'Unexpected response' };

    if (res.data.query_status === 'no_result') {
      return { provider: 'ThreatFox', found: false, link: 'https://threatfox.abuse.ch/' };
    }

    const items = res.data.data || [];
    if (!items.length) {
      return { provider: 'ThreatFox', found: false, link: 'https://threatfox.abuse.ch/' };
    }

    const first = items[0];
    return {
      provider: 'ThreatFox',
      found: true,
      total_matches: items.length,
      threat_type: first.threat_type,
      malware: first.malware_printable,
      malware_alias: first.malware_alias,
      confidence_level: first.confidence_level,
      first_seen: first.first_seen_utc,
      last_seen: first.last_seen_utc,
      tags: first.tags,
      reference: first.reference,
      link: first.ioc_id ? `https://threatfox.abuse.ch/ioc/${first.ioc_id}/` : 'https://threatfox.abuse.ch/',
    };
  } catch (err) {
    return { provider: 'ThreatFox', error: err.message };
  }
}

// --- Provider: MalwareBazaar (abuse.ch) — no key required ---

async function queryMalwareBazaar(apiKey, iocValue, iocType) {
  if (iocType !== 'hash') {
    return { provider: 'MalwareBazaar', error: 'Only supports hash lookups (MD5, SHA1, SHA256)' };
  }

  try {
    const formBody = `query=get_info&hash=${encodeURIComponent(iocValue)}`;
    const res = await fetchJSON('https://mb-api.abuse.ch/api/v1/', {
      method: 'POST',
      body: formBody,
      contentType: 'application/x-www-form-urlencoded',
    });

    if (res.status !== 200) return { provider: 'MalwareBazaar', error: `HTTP ${res.status}` };
    if (!res.data) return { provider: 'MalwareBazaar', error: 'Unexpected response' };

    if (res.data.query_status === 'hash_not_found' || res.data.query_status === 'no_results') {
      return { provider: 'MalwareBazaar', found: false, link: 'https://bazaar.abuse.ch/' };
    }

    const d = res.data.data && res.data.data[0];
    if (!d) return { provider: 'MalwareBazaar', found: false, link: 'https://bazaar.abuse.ch/' };

    return {
      provider: 'MalwareBazaar',
      found: true,
      sha256: d.sha256_hash,
      md5: d.md5_hash,
      sha1: d.sha1_hash,
      file_name: d.file_name,
      file_type: d.file_type,
      file_size: d.file_size,
      signature: d.signature,
      tags: d.tags,
      first_seen: d.first_seen,
      last_seen: d.last_seen,
      intelligence: d.intelligence,
      link: d.sha256_hash ? `https://bazaar.abuse.ch/sample/${d.sha256_hash}/` : 'https://bazaar.abuse.ch/',
    };
  } catch (err) {
    return { provider: 'MalwareBazaar', error: err.message };
  }
}

// --- Main lookup function ---

const PROVIDERS = {
  virustotal: { name: 'VirusTotal', fn: queryVirusTotal, requiresKey: true },
  abuseipdb: { name: 'AbuseIPDB', fn: queryAbuseIPDB, requiresKey: true },
  threatfox: { name: 'ThreatFox', fn: queryThreatFox, requiresKey: false },
  malwarebazaar: { name: 'MalwareBazaar', fn: queryMalwareBazaar, requiresKey: false },
};

/**
 * Look up an IOC across selected providers.
 * @param {string} iocValue - The IOC to look up
 * @param {Object} apiKeys - { virustotal: 'key', abuseipdb: 'key', ... }
 * @param {string[]} providers - Provider IDs to query (defaults to all with keys)
 * @returns {Object} { ioc, type, results: [...] }
 */
async function lookupIOC(iocValue, apiKeys = {}, providers = null) {
  const iocType = detectIOCType(iocValue);
  if (!iocType) {
    return { ioc: iocValue, type: null, error: 'Could not detect IOC type. Supported: IPv4, domain, MD5, SHA1, SHA256, URL.' };
  }

  const selectedProviders = providers || Object.keys(PROVIDERS);
  const tasks = [];

  for (const pid of selectedProviders) {
    const provider = PROVIDERS[pid];
    if (!provider) continue;
    if (provider.requiresKey && !apiKeys[pid]) continue;
    tasks.push(provider.fn(apiKeys[pid] || '', iocValue, iocType));
  }

  if (tasks.length === 0) {
    return { ioc: iocValue, type: iocType, error: 'No providers available. Add API keys or select providers that don\'t require keys.' };
  }

  const results = await Promise.allSettled(tasks);
  return {
    ioc: iocValue,
    type: iocType,
    results: results.map(r => r.status === 'fulfilled' ? r.value : { error: r.reason.message }),
  };
}

module.exports = { lookupIOC, detectIOCType, PROVIDERS };
