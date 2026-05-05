const geoip = require('geoip-lite');
const db = require('../db');

// Mapping of ISO-2 codes to human-readable country names
const COUNTRY_NAMES = {
  'US': 'United States',
  'GB': 'United Kingdom',
  'CN': 'China',
  'RU': 'Russia',
  'DE': 'Germany',
  'FR': 'France',
  'JP': 'Japan',
  'IN': 'India',
  'BR': 'Brazil',
  'CA': 'Canada',
  'AU': 'Australia',
  'NL': 'Netherlands',
  'SE': 'Sweden',
  'CH': 'Switzerland',
  'IT': 'Italy',
  'ES': 'Spain',
  'KR': 'South Korea',
  'SG': 'Singapore',
  'MX': 'Mexico',
  'IR': 'Iran',
  'KP': 'North Korea',
  'SY': 'Syria',
  'PK': 'Pakistan',
  'NG': 'Nigeria',
  'ZA': 'South Africa',
  'UA': 'Ukraine',
  'PL': 'Poland',
  'TR': 'Turkey',
  'TH': 'Thailand',
  'VN': 'Vietnam',
  'ID': 'Indonesia',
  'MY': 'Malaysia',
  'PH': 'Philippines',
  'IL': 'Israel',
  'SA': 'Saudi Arabia',
  'AE': 'United Arab Emirates',
  'EG': 'Egypt',
  'NG': 'Nigeria',
  'KE': 'Kenya',
  'BO': 'Bolivia',
  'CU': 'Cuba',
  'VE': 'Venezuela',
  'CZ': 'Czech Republic',
  'BE': 'Belgium',
  'AT': 'Austria',
  'GR': 'Greece',
  'PT': 'Portugal',
  'NO': 'Norway',
  'DK': 'Denmark',
  'FI': 'Finland',
  'HU': 'Hungary',
  'RO': 'Romania',
  'BG': 'Bulgaria',
  'HR': 'Croatia',
  'RS': 'Serbia',
  'HK': 'Hong Kong',
  'TW': 'Taiwan',
  'NZ': 'New Zealand',
  'AR': 'Argentina',
  'CL': 'Chile',
  'CO': 'Colombia',
  'PE': 'Peru',
};

/**
 * Lookup IP geolocation data.
 * @param {string} ip - IPv4 address
 * @returns {object|null} - {country, country_name, lat, lon, city} or null on failure
 */
function lookup(ip) {
  try {
    const result = geoip.lookup(ip);
    if (!result) return null;

    const countryName = COUNTRY_NAMES[result.country] || result.country;

    return {
      country: result.country,
      country_name: countryName,
      lat: result.ll ? result.ll[0] : null,
      lon: result.ll ? result.ll[1] : null,
      city: result.city || null,
    };
  } catch (err) {
    console.error(`[GeoIP] Lookup failed for ${ip}:`, err.message);
    return null;
  }
}

/**
 * Skip private/reserved IP ranges.
 * @param {string} ip - IPv4 address
 * @returns {boolean} - true if IP should be skipped
 */
function isPrivateOrReserved(ip) {
  const octets = ip.split('.').map(Number);
  if (octets.length !== 4) return true;

  // 10.0.0.0/8
  if (octets[0] === 10) return true;

  // 127.0.0.0/8 (loopback)
  if (octets[0] === 127) return true;

  // 169.254.0.0/16 (link-local)
  if (octets[0] === 169 && octets[1] === 254) return true;

  // 172.16.0.0/12
  if (octets[0] === 172 && octets[1] >= 16 && octets[1] <= 31) return true;

  // 192.168.0.0/16
  if (octets[0] === 192 && octets[1] === 168) return true;

  // 224.0.0.0/4 (multicast)
  if (octets[0] >= 224 && octets[0] <= 239) return true;

  // 240.0.0.0/4 (reserved)
  if (octets[0] >= 240) return true;

  return false;
}

/**
 * Upsert IP geolocation data into ioc_geo table.
 * @param {string} ip - IPv4 address
 * @param {object} options - {source, article_id, darkweb_hit_id}
 * @returns {number|null} - row id on success, null on skip or failure
 */
function upsertIp(ip, options = {}) {
  try {
    // Skip private/reserved IPs
    if (isPrivateOrReserved(ip)) {
      return null;
    }

    const geoData = lookup(ip);
    if (!geoData) {
      return null;
    }

    const now = Date.now();
    const { source, article_id, darkweb_hit_id } = options;

    // Use UPSERT (INSERT ... ON CONFLICT) to handle duplicates
    const stmt = db.prepare(`
      INSERT INTO ioc_geo (ip, country, country_name, lat, lon, first_seen, last_seen, source, article_id, darkweb_hit_id)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
      ON CONFLICT(ip) DO UPDATE SET
        last_seen = excluded.last_seen,
        source = COALESCE(excluded.source, source),
        article_id = COALESCE(excluded.article_id, article_id),
        darkweb_hit_id = COALESCE(excluded.darkweb_hit_id, darkweb_hit_id)
    `);

    const result = stmt.run(
      ip,
      geoData.country,
      geoData.country_name,
      geoData.lat,
      geoData.lon,
      now,
      now,
      source || null,
      article_id || null,
      darkweb_hit_id || null
    );

    return result.lastInsertRowid || null;
  } catch (err) {
    console.error(`[GeoIP] Upsert failed for ${ip}:`, err.message);
    return null;
  }
}

module.exports = {
  lookup,
  upsertIp,
};
