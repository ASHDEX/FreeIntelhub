/**
 * AI Context Service — keyless intelligence brief generator
 *
 * Tier 1 (always available): local extractive analysis derived from
 *   entity metadata + article titles already in SQLite. Zero API keys.
 *
 * Tier 2 (optional): Ollama local LLM. Activated when OLLAMA_HOST is set
 *   in the environment. Falls back to Tier 1 silently on any error.
 *
 * Results cached in SQLite (24-hour TTL) to avoid recomputing on every visit.
 */

'use strict';

const db = require('../db');

// ── Cache helpers ─────────────────────────────────────────────────────────────

const cacheStmts = {
  get: db.prepare(`
    SELECT summary_json, generated_at FROM ai_summaries
    WHERE entity_type = ? AND entity_id = ?
      AND generated_at >= datetime('now', '-24 hours')
  `),
  upsert: db.prepare(`
    INSERT OR REPLACE INTO ai_summaries (entity_type, entity_id, summary_json, generated_at)
    VALUES (?, ?, ?, datetime('now'))
  `),
};

// ── In-flight deduplication ───────────────────────────────────────────────────

const inFlight = new Map(); // key: `${type}:${entityId}` → Promise

// ── Keyword helpers ───────────────────────────────────────────────────────────

const TTP_KEYWORDS = [
  'phishing', 'spearphishing', 'ransomware', 'exploit', 'backdoor', 'trojan',
  'rootkit', 'keylogger', 'lateral movement', 'privilege escalation', 'credential',
  'c2', 'command and control', 'supply chain', 'zero-day', '0-day', 'brute force',
  'sql injection', 'xss', 'watering hole', 'drive-by', 'malware', 'wiper',
  'loader', 'dropper', 'stealer', 'botnet', 'ddos', 'data exfiltration',
];

const SECTOR_KEYWORDS = [
  'healthcare', 'hospital', 'medical', 'finance', 'banking', 'financial',
  'government', 'federal', 'military', 'defence', 'defense', 'energy',
  'utilities', 'oil', 'gas', 'retail', 'manufacturing', 'technology',
  'telecom', 'critical infrastructure', 'education', 'university',
  'transportation', 'logistics', 'aerospace',
];

const TTP_DEFENCES = {
  'phishing': 'Deploy anti-phishing email filtering and user awareness training',
  'spearphishing': 'Enable advanced email inspection and DMARC/DKIM/SPF policies',
  'ransomware': 'Maintain tested offline backups and enforce least-privilege',
  'exploit': 'Prioritise patching of internet-facing assets and use exploit mitigations',
  'backdoor': 'Monitor for unexpected outbound connections and unusual process trees',
  'credential': 'Enforce MFA and monitor for credential-based lateral movement',
  'c2': 'Block known C2 frameworks and monitor DNS/HTTP beaconing patterns',
  'command and control': 'Block known C2 frameworks and monitor DNS/HTTP beaconing patterns',
  'supply chain': 'Audit third-party software integrity and enforce code-signing policies',
  'zero-day': 'Apply virtual patching at the network/WAF layer for critical assets',
  '0-day': 'Apply virtual patching at the network/WAF layer for critical assets',
  'privilege escalation': 'Apply Just-in-Time privileged access and monitor for token abuse',
  'lateral movement': 'Segment the network and enforce host-based firewall rules',
  'data exfiltration': 'Monitor large outbound data transfers and enable DLP controls',
  'brute force': 'Enforce account lockout policies and monitor failed authentication events',
};

function extractKeywords(texts, keywords) {
  const combined = texts.join(' ').toLowerCase();
  const found = new Set();
  for (const kw of keywords) {
    if (combined.includes(kw)) found.add(kw.charAt(0).toUpperCase() + kw.slice(1));
  }
  return [...found];
}

function defensesForTtps(ttps) {
  const defences = new Set();
  for (const ttp of ttps) {
    const key = ttp.toLowerCase();
    if (TTP_DEFENCES[key]) defences.add(TTP_DEFENCES[key]);
  }
  // Always include a baseline if we have nothing specific
  if (defences.size === 0) {
    defences.add('Apply defence-in-depth and monitor for anomalous behaviour');
    defences.add('Keep all software patched and reduce the internet-exposed attack surface');
  }
  // Cap at 4
  return [...defences].slice(0, 4);
}

function activityAssessment(articles) {
  const now = Date.now();
  const MS = { d30: 30 * 864e5, d90: 90 * 864e5, d365: 365 * 864e5 };
  let c30 = 0, c90 = 0, c365 = 0, total = articles.length;

  for (const a of articles) {
    const age = now - new Date(a.published_at || a.date || 0).getTime();
    if (age <= MS.d30) c30++;
    if (age <= MS.d90) c90++;
    if (age <= MS.d365) c365++;
  }

  if (total === 0) return 'No intelligence articles are currently linked to this entity.';
  if (c30 >= 3) return `This entity is highly active — ${c30} articles recorded in the last 30 days. Ongoing monitoring is strongly advised.`;
  if (c30 >= 1) return `Recent activity detected — ${c30} article${c30 > 1 ? 's' : ''} in the last 30 days, with ${c90} in the last 90 days. Treat as an active threat.`;
  if (c90 >= 1) return `Activity has slowed recently — last seen in the 30–90 day window (${c90} article${c90 > 1 ? 's' : ''}). Continue monitoring.`;
  if (c365 >= 1) return `Limited recent activity — ${c365} article${c365 > 1 ? 's' : ''} in the past year but none in the last 90 days. May be dormant.`;
  return `No activity in the past year. Entity may be defunct, rebranded, or attribution is low-confidence.`;
}

// ── Malpedia helpers ──────────────────────────────────────────────────────────

function malpediaAttribution(entity) {
  try { return JSON.parse(entity.malpedia_attribution || '[]'); } catch (_) { return []; }
}

function malpediaRefs(entity) {
  try { return JSON.parse(entity.malpedia_refs || '[]'); } catch (_) { return []; }
}

// ── Tier 1: local extractive analysis ────────────────────────────────────────

function buildLocalBrief(type, entity, articles) {
  const titles = articles.map(a => a.title || '');
  const hasM = !!entity.malpedia_uuid; // Malpedia-verified flag

  if (type === 'threat-group') {
    const ttps = extractKeywords(titles, TTP_KEYWORDS);
    const sectors = extractKeywords(titles, SECTOR_KEYWORDS);
    const articleCount = articles.length;
    const refs = malpediaRefs(entity);
    return {
      attribution_confidence: entity.country
        ? `${hasM ? 'High (Malpedia-verified)' : 'High'} — attributed to ${entity.country} based on group metadata and reporting`
        : hasM ? 'Medium (Malpedia-verified) — country attribution not confirmed'
        : 'Low — no confirmed country attribution in current data',
      sophistication_level: articleCount >= 20
        ? 'Advanced — high volume of intelligence reporting indicates a prolific, well-resourced actor'
        : articleCount >= 5
          ? 'Moderate — consistent reporting suggests an established threat actor'
          : 'Unknown — insufficient intelligence to assess sophistication',
      primary_ttps: ttps.length ? ttps.slice(0, 5) : ['Tactics not yet identified from available reporting'],
      recent_activity_assessment: activityAssessment(articles),
      targeted_sectors: sectors.length ? sectors.slice(0, 5) : ['Sector targeting not yet identified from available reporting'],
      recommended_defensive_actions: defensesForTtps(ttps),
      analyst_note: (entity.description || '').slice(0, 280) || 'No description available for this threat group.'
        + (refs.length ? ` ${refs.length} Malpedia research references available.` : ''),
    };
  }

  if (type === 'software') {
    const ttps = extractKeywords(titles, TTP_KEYWORDS);
    const sectors = extractKeywords(titles, SECTOR_KEYWORDS);
    const swType = entity.type || 'software';
    const attribution = malpediaAttribution(entity);
    return {
      capability_summary: (entity.description || '').slice(0, 280)
        || `${entity.name} is a ${swType}. Detailed capability information is not yet available.`,
      technical_characteristics: ttps.length
        ? ttps.slice(0, 4)
        : ['Technical characteristics not yet identified from available reporting'],
      infection_vectors: extractKeywords(titles, ['phishing', 'exploit', 'drive-by', 'supply chain', 'usb', 'macro', 'loader']).slice(0, 3),
      detection_advice: defensesForTtps(ttps).slice(0, 3),
      similar_malware_families: attribution.length ? attribution.slice(0, 4) : [],
      recent_activity_assessment: activityAssessment(articles),
      analyst_note: attribution.length
        ? `Used by: ${attribution.slice(0, 3).join(', ')}. ${sectors.length ? `Primarily targeting ${sectors.slice(0, 2).join(' and ')}.` : ''}`
        : sectors.length
          ? `Primarily observed targeting ${sectors.slice(0, 2).join(' and ')} — prioritise detection in those environments.`
          : 'Monitor for indicators in threat feeds and apply defence-in-depth controls.',
    };
  }

  if (type === 'campaign') {
    const ttps = extractKeywords(titles, TTP_KEYWORDS);
    const sectors = extractKeywords(titles, SECTOR_KEYWORDS);
    const assoc = Array.isArray(entity.associated_groups) && entity.associated_groups.length
      ? entity.associated_groups.join(', ') : null;
    return {
      objectives: (entity.description || '').slice(0, 280)
        || `Campaign objectives for ${entity.name} are not yet established from available reporting.`,
      timeline: entity.first_seen
        ? `First observed ${entity.first_seen}. ${articles.length} intelligence articles linked.`
        : `Timeline not established. ${articles.length} intelligence article${articles.length !== 1 ? 's' : ''} linked.`,
      targeted_sectors: sectors.length ? sectors.slice(0, 4) : ['Targeting not yet identified'],
      attack_chain_summary: ttps.length
        ? ttps.slice(0, 4).map((t, i) => `Phase ${i + 1}: ${t}`)
        : ['Attack chain not yet reconstructed from available reporting'],
      indicators_to_hunt: defensesForTtps(ttps).slice(0, 3),
      recent_activity_assessment: activityAssessment(articles),
      analyst_note: assoc
        ? `Associated with ${assoc} — review actor-level TTPs for additional defensive context.`
        : 'Review linked articles for specific indicators and hunting opportunities.',
    };
  }

  throw new Error(`Unknown entity type: ${type}`);
}

// ── Tier 2: Ollama (optional) ─────────────────────────────────────────────────

function buildPrompt(type, entity, articles) {
  const snippets = articles.length
    ? articles.map((a, i) => `[${i + 1}] "${a.title}"\n    ${(a.summary || '').slice(0, 250)}`).join('\n')
    : 'No recent articles available.';

  // Malpedia enrichment block (appended to prompt when data is available)
  const attribution = malpediaAttribution(entity);
  const refs = malpediaRefs(entity);
  const malpediaBlock = [
    attribution.length ? `Malpedia Attribution (actors using this malware): ${attribution.join(', ')}` : '',
    refs.length ? `Malpedia Research References (${refs.length} total): ${refs.slice(0, 3).join(', ')}` : '',
    entity.malpedia_slug ? `Malpedia Slug: ${entity.malpedia_slug}` : '',
  ].filter(Boolean).join('\n');

  if (type === 'threat-group') {
    return `You are a senior threat intelligence analyst. Produce a structured CTI brief for this threat actor.

ENTITY:
Name: ${entity.name}
Type: ${entity.type || 'unknown'}
Country: ${entity.country || 'Unknown'}
MITRE ATT&CK ID: ${entity.mitre_group_id || 'Not mapped'}
Aliases: ${Array.isArray(entity.aliases) && entity.aliases.length ? entity.aliases.join(', ') : 'None'}
Description: ${entity.description || 'No description'}
${malpediaBlock ? `\nMALPEDIA INTELLIGENCE:\n${malpediaBlock}` : ''}

RECENT ARTICLES:
${snippets}

Respond with ONLY valid JSON, no markdown:
{"attribution_confidence":"...","sophistication_level":"...","primary_ttps":[],"recent_activity_assessment":"...","targeted_sectors":[],"recommended_defensive_actions":[],"analyst_note":"..."}`;
  }

  if (type === 'software') {
    return `You are a senior threat intelligence analyst. Produce a structured CTI brief for this malware or tool.

ENTITY:
Name: ${entity.name}
Type: ${entity.type || 'unknown'}
Aliases: ${Array.isArray(entity.aliases) && entity.aliases.length ? entity.aliases.join(', ') : 'None'}
Description: ${entity.description || 'No description'}
${malpediaBlock ? `\nMALPEDIA INTELLIGENCE:\n${malpediaBlock}` : ''}

RECENT ARTICLES:
${snippets}

Respond with ONLY valid JSON, no markdown:
{"capability_summary":"...","technical_characteristics":[],"infection_vectors":[],"detection_advice":[],"similar_malware_families":[],"recent_activity_assessment":"...","analyst_note":"..."}`;
  }

  if (type === 'campaign') {
    const assoc = Array.isArray(entity.associated_groups) && entity.associated_groups.length
      ? entity.associated_groups.join(', ') : 'Unknown';
    return `You are a senior threat intelligence analyst. Produce a structured CTI brief for this campaign.

ENTITY:
Name: ${entity.name}
Associated Groups: ${assoc}
Aliases: ${Array.isArray(entity.aliases) && entity.aliases.length ? entity.aliases.join(', ') : 'None'}
First Seen: ${entity.first_seen || 'Unknown'}
Description: ${entity.description || 'No description'}
${malpediaBlock ? `\nMALPEDIA INTELLIGENCE:\n${malpediaBlock}` : ''}

RECENT ARTICLES:
${snippets}

Respond with ONLY valid JSON, no markdown:
{"objectives":"...","timeline":"...","targeted_sectors":[],"attack_chain_summary":[],"indicators_to_hunt":[],"recent_activity_assessment":"...","analyst_note":"..."}`;
  }

  throw new Error(`Unknown entity type: ${type}`);
}

async function callGroq(type, entity, articles) {
  const model = process.env.GROQ_MODEL || 'llama-3.1-8b-instant';
  const prompt = buildPrompt(type, entity, articles);

  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), 20000);

  try {
    const resp = await fetch('https://api.groq.com/openai/v1/chat/completions', {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${process.env.GROQ_API_KEY}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        model,
        messages: [{ role: 'user', content: prompt }],
        temperature: 0.3,
        max_tokens: 900,
      }),
      signal: controller.signal,
    });
    if (!resp.ok) {
      const err = await resp.json().catch(() => ({}));
      throw new Error(`Groq HTTP ${resp.status}: ${err.error?.message || 'unknown'}`);
    }
    const data = await resp.json();
    const text = (data.choices?.[0]?.message?.content || '').trim()
      .replace(/^```(?:json)?\s*/i, '').replace(/\s*```$/i, '').trim();
    return JSON.parse(text);
  } finally {
    clearTimeout(timer);
  }
}

async function callOllama(type, entity, articles) {
  const host = process.env.OLLAMA_HOST || 'http://127.0.0.1:11434';
  const model = process.env.OLLAMA_MODEL || 'llama3.2';
  const prompt = buildPrompt(type, entity, articles);

  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), 15000);

  try {
    const resp = await fetch(`${host}/api/generate`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ model, prompt, stream: false }),
      signal: controller.signal,
    });
    if (!resp.ok) throw new Error(`Ollama HTTP ${resp.status}`);
    const data = await resp.json();
    const text = (data.response || '').trim()
      .replace(/^```(?:json)?\s*/i, '').replace(/\s*```$/i, '').trim();
    return JSON.parse(text);
  } finally {
    clearTimeout(timer);
  }
}

// ── Public API ────────────────────────────────────────────────────────────────

async function getAiContext(type, entityId, entity, articles) {
  // 1. Return cached result if fresh (< 24h)
  const cached = cacheStmts.get.get(type, entityId);
  if (cached) {
    return { ...JSON.parse(cached.summary_json), generated_at: cached.generated_at, cached: true };
  }

  // 2. Deduplicate concurrent calls for the same entity
  const key = `${type}:${entityId}`;
  if (inFlight.has(key)) return inFlight.get(key);

  const promise = (async () => {
    try {
      let sections;

      // 3a. Groq (free cloud LLM, fastest)
      if (process.env.GROQ_API_KEY) {
        try {
          sections = await callGroq(type, entity, articles);
        } catch (err) {
          console.warn(`[AI] Groq error (${err.message}), falling back`);
          sections = buildLocalBrief(type, entity, articles);
        }
      // 3b. Ollama (local LLM, no API key)
      } else if (process.env.OLLAMA_HOST) {
        try {
          sections = await callOllama(type, entity, articles);
        } catch (err) {
          console.warn(`[AI] Ollama unavailable (${err.message}), falling back to local analysis`);
          sections = buildLocalBrief(type, entity, articles);
        }
      // 3c. Local extractive analysis (zero dependencies, always works)
      } else {
        sections = buildLocalBrief(type, entity, articles);
      }

      const payload = { sections, generated_at: new Date().toISOString(), cached: false };
      cacheStmts.upsert.run(type, entityId, JSON.stringify(payload));
      return payload;
    } finally {
      inFlight.delete(key);
    }
  })();

  inFlight.set(key, promise);
  return promise;
}

module.exports = { getAiContext };
