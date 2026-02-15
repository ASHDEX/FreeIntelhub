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

module.exports = { getLatestCVEs };
