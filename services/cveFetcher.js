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

// Generic HTTPS JSON fetcher with timeout
function fetchJSON(url, timeout = 8000) {
  return new Promise((resolve, reject) => {
    const mod = url.startsWith('https') ? https : require('http');
    const req = mod.get(url, { headers: { 'User-Agent': 'FreeIntelHub/1.0', 'Accept': 'application/json' } }, (res) => {
      let data = '';
      res.on('data', (chunk) => { data += chunk; });
      res.on('end', () => {
        try { resolve(JSON.parse(data)); } catch (e) { reject(e); }
      });
    });
    req.on('error', reject);
    req.setTimeout(timeout, () => { req.destroy(); reject(new Error('timeout')); });
  });
}

// --- Individual source fetchers ---

function fetchNVD(id) {
  return fetchJSON(`https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=${encodeURIComponent(id)}`).then(json => {
    const vulns = json.vulnerabilities || [];
    if (vulns.length === 0) return null;
    const cve = vulns[0].cve || {};
    const desc = (cve.descriptions || []).find(d => d.lang === 'en');
    const refs = (cve.references || []).map(r => ({ url: r.url, source: r.source || '' }));
    const metrics = cve.metrics || {};
    let severity = '', score = null, vector = '';
    if (metrics.cvssMetricV31 && metrics.cvssMetricV31.length) {
      severity = metrics.cvssMetricV31[0].cvssData.baseSeverity || '';
      score = metrics.cvssMetricV31[0].cvssData.baseScore || null;
      vector = metrics.cvssMetricV31[0].cvssData.vectorString || '';
    } else if (metrics.cvssMetricV2 && metrics.cvssMetricV2.length) {
      severity = metrics.cvssMetricV2[0].baseSeverity || '';
      score = metrics.cvssMetricV2[0].cvssData.baseScore || null;
      vector = metrics.cvssMetricV2[0].cvssData.vectorString || '';
    }
    const weaknesses = (cve.weaknesses || []).flatMap(w => (w.description || []).map(d => d.value)).filter(v => v !== 'NVD-CWE-noinfo');
    return {
      id: cve.id,
      description: desc ? desc.value : '',
      severity, score, vector, weaknesses,
      references: refs.slice(0, 15),
      published: cve.published || null,
      lastModified: cve.lastModified || null,
      configurations: (cve.configurations || []),
    };
  });
}

function fetchOSV(id) {
  return new Promise((resolve, reject) => {
    const postData = JSON.stringify({ query: id });
    const options = {
      hostname: 'api.osv.dev', port: 443, path: '/v1/query',
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'User-Agent': 'FreeIntelHub/1.0', 'Content-Length': Buffer.byteLength(postData) },
    };
    const req = https.request(options, (res) => {
      let data = '';
      res.on('data', (chunk) => { data += chunk; });
      res.on('end', () => {
        try {
          const json = JSON.parse(data);
          const vulns = json.vulns || [];
          const match = vulns.find(v => (v.aliases || []).includes(id) || v.id === id);
          if (!match) return resolve(null);
          const affected = (match.affected || []).map(a => ({
            package: a.package ? `${a.package.ecosystem}/${a.package.name}` : '',
            ranges: (a.ranges || []).map(r => r.events || []),
          }));
          resolve({
            osv_id: match.id,
            summary: match.summary || '',
            details: (match.details || '').slice(0, 500),
            affected,
            references: (match.references || []).map(r => ({ url: r.url, type: r.type })).slice(0, 10),
          });
        } catch (e) { reject(e); }
      });
    });
    req.on('error', reject);
    req.setTimeout(8000, () => { req.destroy(); reject(new Error('timeout')); });
    req.write(postData);
    req.end();
  });
}

function fetchGitHubAdvisory(id) {
  return fetchJSON(`https://api.github.com/advisories?cve_id=${encodeURIComponent(id)}`).then(data => {
    if (!Array.isArray(data) || data.length === 0) return null;
    const adv = data[0];
    return {
      ghsa_id: adv.ghsa_id || '',
      summary: adv.summary || '',
      severity: adv.severity || '',
      html_url: adv.html_url || '',
      published_at: adv.published_at || null,
      updated_at: adv.updated_at || null,
      vulnerabilities: (adv.vulnerabilities || []).map(v => ({
        package: v.package ? `${v.package.ecosystem}/${v.package.name}` : '',
        vulnerable_range: v.vulnerable_version_range || '',
        patched: v.first_patched_version ? v.first_patched_version.identifier : null,
      })).slice(0, 10),
      cwes: (adv.cwes || []).map(c => c.cwe_id || c),
    };
  });
}

function fetchCISAKEV(id) {
  return fetchJSON('https://www.cisa.gov/sites/default/files/feeds/known-exploited-vulnerabilities.json').then(json => {
    const vulns = json.vulnerabilities || [];
    const match = vulns.find(v => v.cveID === id);
    if (!match) return null;
    return {
      exploitedInWild: true,
      vendorProject: match.vendorProject || '',
      product: match.product || '',
      dateAdded: match.dateAdded || '',
      dueDate: match.dueDate || '',
      shortDescription: match.shortDescription || '',
      requiredAction: match.requiredAction || '',
      knownRansomwareCampaignUse: match.knownRansomwareCampaignUse || 'Unknown',
      notes: match.notes || '',
    };
  });
}

// Fetch EPSS (Exploit Prediction Scoring System) from FIRST.org
function fetchEPSS(id) {
  return fetchJSON(`https://api.first.org/data/1.0/epss?cve=${encodeURIComponent(id)}`).then(json => {
    const entry = (json.data || [])[0];
    if (!entry) return null;
    return {
      score: parseFloat(entry.epss) || 0,
      percentile: parseFloat(entry.percentile) || 0,
      date: entry.date || '',
    };
  });
}

// Generate lookup links for databases that don't have free APIs
function generateExternalLinks(id) {
  const encoded = encodeURIComponent(id);
  return {
    vulnerability_databases: [
      { name: 'NIST NVD', url: `https://nvd.nist.gov/vuln/detail/${id}`, category: 'primary' },
      { name: 'MITRE CVE', url: `https://cve.mitre.org/cgi-bin/cvename.cgi?name=${id}`, category: 'primary' },
      { name: 'GitHub Advisory', url: `https://github.com/advisories?query=${encoded}`, category: 'primary' },
      { name: 'OSV.dev', url: `https://osv.dev/vulnerability/${id}`, category: 'primary' },
      { name: 'CloudVulnDB', url: `https://www.cloudvulndb.org/?q=${encoded}`, category: 'cloud' },
      { name: 'Vulners', url: `https://vulners.com/cve/${id}`, category: 'aggregator' },
      { name: 'OpenCVE', url: `https://www.opencve.io/cve/${id}`, category: 'aggregator' },
      { name: 'Snyk', url: `https://security.snyk.io/vuln?search=${encoded}`, category: 'aggregator' },
      { name: 'Mend (WhiteSource)', url: `https://www.mend.io/vulnerability-database/search?query=${encoded}`, category: 'aggregator' },
      { name: 'Rapid7 VulnDB', url: `https://www.rapid7.com/db/?q=${encoded}&type=nexpose`, category: 'aggregator' },
      { name: 'CVE Details', url: `https://www.cvedetails.com/cve/${id}/`, category: 'aggregator' },
      { name: 'VulnIQ', url: `https://vulniq.com/cve/${id}`, category: 'aggregator' },
      { name: 'SynapsInt', url: `https://synapsint.com/report.php?q=${encoded}`, category: 'osint' },
      { name: 'Aqua VulnDB', url: `https://avd.aquasec.com/nvd/${id.toLowerCase()}`, category: 'cloud' },
      { name: 'Vulmon', url: `https://vulmon.com/vulnerabilitydetails?qid=${id}`, category: 'aggregator' },
      { name: 'VulDB', url: `https://vuldb.com/?search=${encoded}`, category: 'aggregator' },
      { name: 'Trend Micro ZDI', url: `https://www.zerodayinitiative.com/advisories/published/?q=${encoded}`, category: 'zeroday' },
      { name: 'Google Project Zero', url: `https://bugs.chromium.org/p/project-zero/issues/list?q=${encoded}`, category: 'zeroday' },
      { name: 'Trickest CVE', url: `https://github.com/trickest/cve/find/main?q=${encoded}`, category: 'poc' },
      { name: 'CNVD (China)', url: `https://www.cnvd.org.cn/flaw/show?keyword=${encoded}`, category: 'national' },
      { name: 'InTheWild.io', url: `https://inthewild.io/vuln/${id}`, category: 'exploitation' },
      { name: 'Vulnerability Lab', url: `https://www.vulnerability-lab.com/search.php?search=${encoded}`, category: 'aggregator' },
      { name: 'Red Hat Security', url: `https://access.redhat.com/security/cve/${id}`, category: 'vendor' },
      { name: 'Cisco Security', url: `https://sec.cloudapps.cisco.com/security/center/search.x?search=${encoded}`, category: 'vendor' },
      { name: 'Microsoft MSRC', url: `https://msrc.microsoft.com/update-guide/vulnerability/${id}`, category: 'vendor' },
      { name: 'VARIoT', url: `https://www.variotdbs.pl/vulns/?search=${encoded}`, category: 'iot' },
      { name: 'cvefeed.io', url: `https://cvefeed.io/vuln/detail/${id}`, category: 'aggregator' },
      { name: 'CVE Crowd', url: `https://cvecrowd.com/cve/${id}`, category: 'community' },
      { name: 'Wiz VulnDB', url: `https://www.wiz.io/vulnerability-database?cveId=${encoded}`, category: 'cloud' },
      { name: 'Shodan CVEDB', url: `https://cvedb.shodan.io/cve/${id}`, category: 'aggregator' },
      { name: 'Vulert', url: `https://vulert.com/vuln-db/search?query=${encoded}`, category: 'aggregator' },
      { name: 'ScanFactory', url: `https://in.scanfactory.io/cvemon/${id}.html`, category: 'aggregator' },
      { name: 'Coalition ESS', url: `https://ess.coalitioninc.com/cve/${id}`, category: 'scoring' },
    ],
    exploit_databases: [
      { name: 'Exploit-DB', url: `https://www.exploit-db.com/search?cve=${id.replace('CVE-', '')}`, category: 'exploit' },
      { name: 'Sploitus', url: `https://sploitus.com/?query=${encoded}#exploits`, category: 'exploit' },
      { name: 'Rapid7 Exploits', url: `https://www.rapid7.com/db/?q=${encoded}&type=metasploit`, category: 'exploit' },
      { name: 'Vulmon Exploits', url: `https://vulmon.com/searchpage?q=${encoded}&type=exploits`, category: 'exploit' },
      { name: 'Packet Storm', url: `https://packetstormsecurity.com/search/?q=${encoded}`, category: 'exploit' },
      { name: '0day.today', url: `https://0day.today/search?search_request=${encoded}`, category: 'exploit' },
      { name: 'ExploitAlert', url: `https://www.exploitalert.com/search-results.html?search=${encoded}`, category: 'exploit' },
      { name: 'CVExploits', url: `https://cvexploits.io/search?query=${encoded}`, category: 'exploit' },
      { name: 'VulnCheck XDB', url: `https://vulncheck.com/xdb?cveId=${encoded}`, category: 'exploit' },
      { name: 'exploit.observer', url: `https://exploit.observer/?keyword=${encoded}`, category: 'exploit' },
      { name: 'Hacking the Cloud', url: `https://hackingthe.cloud/?q=${encoded}`, category: 'exploit' },
      { name: 'HackerOne Hacktivity', url: `https://hackerone.com/hacktivity?querystring=${encoded}`, category: 'bugbounty' },
      { name: 'hackyx.io', url: `https://hackyx.io/search/?q=${encoded}`, category: 'exploit' },
    ],
  };
}

// --- Single CVE lookup (basic, for search page) ---
function lookupCVE(cveId) {
  const id = cveId.toUpperCase().trim();
  if (!CVE_ID_REGEX.test(id)) return Promise.resolve(null);

  const cached = lookupCache.get(id);
  if (cached && (Date.now() - cached.fetchedAt) < LOOKUP_CACHE_TTL) {
    return Promise.resolve(cached.data);
  }

  return fetchNVD(id).then(result => {
    lookupCache.set(id, { data: result, fetchedAt: Date.now() });
    return result;
  });
}

// --- Full multi-source CVE lookup (for /vulnerability page) ---
const fullLookupCache = new Map();

async function fullCVELookup(cveId) {
  const id = cveId.toUpperCase().trim();
  if (!CVE_ID_REGEX.test(id)) return null;

  const cached = fullLookupCache.get(id);
  if (cached && (Date.now() - cached.fetchedAt) < LOOKUP_CACHE_TTL) {
    return cached.data;
  }

  // Query all free APIs in parallel
  const [nvd, osv, github, cisaKev, epss] = await Promise.allSettled([
    fetchNVD(id),
    fetchOSV(id),
    fetchGitHubAdvisory(id),
    fetchCISAKEV(id),
    fetchEPSS(id),
  ]);

  const nvdData = nvd.status === 'fulfilled' ? nvd.value : null;
  const osvData = osv.status === 'fulfilled' ? osv.value : null;
  const githubData = github.status === 'fulfilled' ? github.value : null;
  const cisaData = cisaKev.status === 'fulfilled' ? cisaKev.value : null;
  const epssData = epss.status === 'fulfilled' ? epss.value : null;

  if (!nvdData && !osvData && !githubData) return null;

  const externalLinks = generateExternalLinks(id);

  // Determine exploitation / PoC status
  const exploitedInWild = !!(cisaData && cisaData.exploitedInWild);
  const hasKnownExploit = exploitedInWild ||
    (nvdData && nvdData.references && nvdData.references.some(r =>
      /exploit|poc|proof.of.concept/i.test(r.source || r.url || '')
    ));

  const result = {
    id,
    // Primary data from NVD
    description: (nvdData && nvdData.description) || (osvData && osvData.summary) || (githubData && githubData.summary) || '',
    severity: (nvdData && nvdData.severity) || (githubData && githubData.severity) || '',
    score: nvdData && nvdData.score,
    vector: (nvdData && nvdData.vector) || '',
    weaknesses: (nvdData && nvdData.weaknesses) || (githubData && githubData.cwes) || [],
    published: (nvdData && nvdData.published) || (githubData && githubData.published_at) || null,
    lastModified: (nvdData && nvdData.lastModified) || (githubData && githubData.updated_at) || null,
    link: `https://nvd.nist.gov/vuln/detail/${id}`,
    references: (nvdData && nvdData.references) || [],
    // Source results
    sources: {
      nvd: nvdData ? { status: 'found', data: nvdData } : { status: 'not_found' },
      osv: osvData ? { status: 'found', data: osvData } : { status: 'not_found' },
      github: githubData ? { status: 'found', data: githubData } : { status: 'not_found' },
      cisa_kev: cisaData ? { status: 'found', data: cisaData } : { status: 'not_found' },
    },
    // Exploitation & PoC status
    exploitedInWild,
    hasKnownExploit,
    cisaKev: cisaData,
    // EPSS score
    epss: epssData,
    // External lookup links
    externalLinks,
  };

  fullLookupCache.set(id, { data: result, fetchedAt: Date.now() });
  return result;
}

module.exports = { getLatestCVEs, lookupCVE, fullCVELookup, CVE_ID_REGEX };
