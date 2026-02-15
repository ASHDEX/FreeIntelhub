/**
 * MITRE ATT&CK Mapper
 * Maps article text to MITRE ATT&CK technique IDs.
 */

const mitreTechniques = require('../config/mitre.json');

/**
 * Detect MITRE ATT&CK techniques in text.
 * Returns an array of { id, name, tactic } or null if none found.
 */
function detectMitreTechniques(text) {
  if (!text) return null;

  const lower = text.toLowerCase();
  const matched = [];
  const seen = new Set();

  for (const [id, technique] of Object.entries(mitreTechniques)) {
    if (seen.has(id)) continue;
    for (const keyword of technique.keywords) {
      if (lower.includes(keyword)) {
        matched.push({
          id,
          name: technique.name,
          tactic: technique.tactic,
        });
        seen.add(id);
        break;
      }
    }
  }

  return matched.length > 0 ? matched : null;
}

module.exports = { detectMitreTechniques };
