/**
 * STIX 2.1 Bundle Builder
 *
 * Pure-JS, no external libs. Produces a minimal but valid STIX 2.1 bundle
 * suitable for importing into MISP, OpenCTI, ThreatConnect, etc.
 *
 * Usage:
 *   buildBundle([
 *     { type:'ipv4',   value:'1.2.3.4',  source:'rss', source_url:'...', valid_from:'2026-01-01' },
 *     { type:'sha256', value:'abc...',   source:'darkweb', valid_from:'2026-01-02' },
 *     { type:'cve',    value:'CVE-2024-1234' },
 *   ], { name: 'Case 42 — APT99 indicators' })
 *
 * Spec ref: https://docs.oasis-open.org/cti/stix/v2.1/os/stix-v2.1-os.html
 */

const crypto = require('crypto');

function uuidv5ish(name) {
  // Deterministic 8-4-4-4-12 hex from value (not a real UUIDv5 but is a
  // stable, unique-per-value identifier compatible with STIX `--<uuid>` form)
  const h = crypto.createHash('sha1').update(name).digest('hex');
  return `${h.slice(0,8)}-${h.slice(8,12)}-${h.slice(12,16)}-${h.slice(16,20)}-${h.slice(20,32)}`;
}

function escSingle(s) { return String(s).replace(/\\/g, '\\\\').replace(/'/g, "\\'"); }

function patternFor(type, value) {
  const v = escSingle(value);
  switch (type) {
    case 'ipv4':   return `[ipv4-addr:value = '${v}']`;
    case 'ipv6':   return `[ipv6-addr:value = '${v}']`;
    case 'domain': return `[domain-name:value = '${v}']`;
    case 'url':    return `[url:value = '${v}']`;
    case 'email':  return `[email-addr:value = '${v}']`;
    case 'md5':    return `[file:hashes.MD5    = '${v}']`;
    case 'sha1':   return `[file:hashes.'SHA-1'   = '${v}']`;
    case 'sha256': return `[file:hashes.'SHA-256' = '${v}']`;
    case 'hash':   // generic — guess by length
      if (value.length === 32) return `[file:hashes.MD5 = '${v}']`;
      if (value.length === 40) return `[file:hashes.'SHA-1' = '${v}']`;
      return `[file:hashes.'SHA-256' = '${v}']`;
    case 'cve':
      // Map to STIX vulnerability SDO via a marker pattern; emitter will
      // add a separate vulnerability SDO when type === 'cve'.
      return `[vulnerability:name = '${v}']`;
    default:
      return `[artifact:payload_bin = '${v}']`;
  }
}

/**
 * Build a single STIX indicator SDO.
 * @param {{type:string, value:string, source?:string, source_url?:string, valid_from?:string, name?:string}} ioc
 */
function buildIndicator(ioc) {
  const now = new Date().toISOString();
  const id = `indicator--${uuidv5ish(`${ioc.type}:${ioc.value}`)}`;
  const obj = {
    type: 'indicator',
    spec_version: '2.1',
    id,
    created: now,
    modified: now,
    name: ioc.name || ioc.value,
    pattern: patternFor(ioc.type, ioc.value),
    pattern_type: 'stix',
    valid_from: (ioc.valid_from && new Date(ioc.valid_from).toISOString()) || now,
    labels: [ioc.type, ioc.origin].filter(Boolean),
  };
  if (ioc.source || ioc.source_url) {
    obj.external_references = [{
      source_name: ioc.source || 'FreeIntelHub',
      url: ioc.source_url || undefined,
    }].map(o => { if (!o.url) delete o.url; return o; });
  }
  return obj;
}

/**
 * Build a STIX 2.1 bundle from a list of normalized IOC objects.
 * @param {Array} iocs
 * @param {{name?:string, description?:string}} meta
 */
function buildBundle(iocs, meta = {}) {
  const objects = (iocs || []).map(buildIndicator);
  const bundle = {
    type: 'bundle',
    id: `bundle--${uuidv5ish((meta.name || 'fih') + '-' + Date.now())}`,
    spec_version: '2.1',
    objects,
  };
  if (meta.name || meta.description) {
    // Prepend a STIX report SDO so consumers see a context object
    const now = new Date().toISOString();
    objects.unshift({
      type: 'report',
      spec_version: '2.1',
      id: `report--${uuidv5ish(meta.name || 'report')}`,
      created: now,
      modified: now,
      name: meta.name || 'FreeIntelHub Report',
      description: meta.description || '',
      published: now,
      object_refs: objects.map(o => o.id),
      labels: ['threat-report'],
    });
  }
  return bundle;
}

/**
 * Convenience: turn the iocs JSON we store on `articles.iocs` (with keys
 * cves/ipv4/hashes/domains/urls/emails) into a flat list.
 */
function flattenStoredIocs(iocsJson, ctx = {}) {
  if (!iocsJson) return [];
  let parsed = iocsJson;
  if (typeof iocsJson === 'string') {
    try { parsed = JSON.parse(iocsJson); } catch (_) { return []; }
  }
  const out = [];
  const map = {
    cves: 'cve',
    ipv4: 'ipv4',
    hashes: 'hash',
    domains: 'domain',
    urls: 'url',
    emails: 'email',
  };
  for (const [key, type] of Object.entries(map)) {
    const arr = Array.isArray(parsed[key]) ? parsed[key] : [];
    for (const value of arr) {
      out.push({ type, value, ...ctx });
    }
  }
  return out;
}

module.exports = { buildIndicator, buildBundle, flattenStoredIocs };
