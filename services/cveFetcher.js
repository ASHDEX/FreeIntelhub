const https = require('https');

let cache = { cves: [], fetchedAt: 0 };
const CACHE_TTL = 30 * 60 * 1000; // 30 minutes

function fetchFromNVD() {
  return new Promise((resolve, reject) => {
    const url = 'https://services.nvd.nist.gov/rest/json/cves/2.0?resultsPerPage=30&startIndex=0';
    const req = https.get(url, { headers: { 'User-Agent': 'FreeIntelHub/1.0' } }, (res) => {
      let data = '';
      res.on('data', (chunk) => { data += chunk; });
      res.on('end', () => {
        try {
          const json = JSON.parse(data);
          const cves = (json.vulnerabilities || []).map((v) => {
            const cve = v.cve || {};
            const id = cve.id || '';
            const desc = (cve.descriptions || []).find(d => d.lang === 'en');
            const description = desc ? desc.value : '';
            const refs = (cve.references || []).slice(0, 1);
            const link = refs.length > 0 ? refs[0].url : `https://nvd.nist.gov/vuln/detail/${id}`;
            // Get CVSS score if available
            const metrics = cve.metrics || {};
            let severity = '';
            if (metrics.cvssMetricV31 && metrics.cvssMetricV31.length) {
              severity = metrics.cvssMetricV31[0].cvssData.baseSeverity || '';
            } else if (metrics.cvssMetricV2 && metrics.cvssMetricV2.length) {
              severity = metrics.cvssMetricV2[0].baseSeverity || '';
            }
            return { id, description: description.slice(0, 120), link, severity };
          });
          resolve(cves);
        } catch (e) {
          reject(e);
        }
      });
    });
    req.on('error', reject);
    req.setTimeout(10000, () => { req.destroy(); reject(new Error('NVD timeout')); });
  });
}

async function getLatestCVEs() {
  const now = Date.now();
  if (cache.cves.length > 0 && (now - cache.fetchedAt) < CACHE_TTL) {
    return cache.cves;
  }
  try {
    const cves = await fetchFromNVD();
    if (cves.length > 0) {
      cache = { cves, fetchedAt: now };
    }
    return cves;
  } catch (err) {
    console.error('CVE fetch error:', err.message);
    return cache.cves; // return stale cache on error
  }
}

// Direct CVE lookup by ID (e.g. CVE-2024-1234)
const CVE_ID_REGEX = /^CVE-\d{4}-\d{4,}$/i;
const lookupCache = new Map();
const LOOKUP_CACHE_TTL = 15 * 60 * 1000; // 15 minutes

function lookupCVE(cveId) {
  const id = cveId.toUpperCase().trim();
  if (!CVE_ID_REGEX.test(id)) return Promise.resolve(null);

  const cached = lookupCache.get(id);
  if (cached && (Date.now() - cached.fetchedAt) < LOOKUP_CACHE_TTL) {
    return Promise.resolve(cached.data);
  }

  return new Promise((resolve, reject) => {
    const url = `https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=${encodeURIComponent(id)}`;
    const req = https.get(url, { headers: { 'User-Agent': 'FreeIntelHub/1.0' } }, (res) => {
      let data = '';
      res.on('data', (chunk) => { data += chunk; });
      res.on('end', () => {
        try {
          const json = JSON.parse(data);
          const vulns = json.vulnerabilities || [];
          if (vulns.length === 0) {
            lookupCache.set(id, { data: null, fetchedAt: Date.now() });
            return resolve(null);
          }
          const cve = vulns[0].cve || {};
          const desc = (cve.descriptions || []).find(d => d.lang === 'en');
          const description = desc ? desc.value : '';
          const refs = (cve.references || []).map(r => ({ url: r.url, source: r.source || '' }));
          const link = `https://nvd.nist.gov/vuln/detail/${cve.id}`;

          // CVSS score
          const metrics = cve.metrics || {};
          let severity = '';
          let score = null;
          if (metrics.cvssMetricV31 && metrics.cvssMetricV31.length) {
            severity = metrics.cvssMetricV31[0].cvssData.baseSeverity || '';
            score = metrics.cvssMetricV31[0].cvssData.baseScore || null;
          } else if (metrics.cvssMetricV2 && metrics.cvssMetricV2.length) {
            severity = metrics.cvssMetricV2[0].baseSeverity || '';
            score = metrics.cvssMetricV2[0].cvssData.baseScore || null;
          }

          const result = {
            id: cve.id,
            description,
            link,
            severity,
            score,
            references: refs.slice(0, 10),
            published: cve.published || null,
            lastModified: cve.lastModified || null,
          };
          lookupCache.set(id, { data: result, fetchedAt: Date.now() });
          resolve(result);
        } catch (e) {
          reject(e);
        }
      });
    });
    req.on('error', reject);
    req.setTimeout(10000, () => { req.destroy(); reject(new Error('NVD lookup timeout')); });
  });
}

module.exports = { getLatestCVEs, lookupCVE, CVE_ID_REGEX };
