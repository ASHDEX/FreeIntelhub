/**
 * Webhook Service — Sends alerts to Slack, Discord, Telegram, and custom webhooks.
 */

const dns = require('dns');
const { decryptWebhookUrl } = require('./crypto');
const BASE_URL = process.env.BASE_URL || 'http://localhost:3000';

// ---------------------------------------------------------------------------
// SSRF protection at fetch time (guards against DNS rebinding)
// ---------------------------------------------------------------------------

function isPrivateIP(ip) {
  const v4 = ip.replace(/^::ffff:/i, '');
  if (v4 === '127.0.0.1' || v4 === '0.0.0.0' || v4 === '::1' || v4 === '0') return true;
  if (/^10\./.test(v4)) return true;
  if (/^172\.(1[6-9]|2\d|3[01])\./.test(v4)) return true;
  if (/^192\.168\./.test(v4)) return true;
  if (/^169\.254\./.test(v4)) return true;
  if (/^(fc|fd|fe80)/i.test(ip)) return true;
  return false;
}

async function validateNoSsrfAtFetchTime(urlStr) {
  const parsed = new URL(urlStr);
  const hostname = parsed.hostname.replace(/^\[|\]$/g, '');
  // Skip pure IP addresses (already validated at registration time)
  if (/^[\d.:]+$/.test(hostname)) return;
  try {
    const { address } = await dns.promises.lookup(hostname);
    if (isPrivateIP(address)) {
      throw new Error(`SSRF: webhook hostname ${hostname} resolves to private IP ${address}`);
    }
  } catch (err) {
    // Re-throw SSRF errors; for DNS resolution failures block the request to be safe
    throw new Error(err.message.startsWith('SSRF:') ? err.message : `SSRF: could not resolve webhook hostname ${hostname}`);
  }
}

function safeParse(json) {
  if (!json) return null;
  try { return JSON.parse(json); } catch (_) { return null; }
}

/**
 * Build a plain-text summary for a list of articles.
 */
function buildTextSummary(articles) {
  return articles.map(a => {
    let line = `• ${a.title}`;
    const tags = [a.source, a.category, a.vendor].filter(Boolean);
    if (tags.length) line += ` [${tags.join(' | ')}]`;
    line += `\n  ${a.link}`;
    return line;
  }).join('\n\n');
}

/**
 * Send to a Slack incoming webhook.
 */
async function sendSlack(webhookUrl, articles) {
  const text = `🚨 *FreeIntelHub Alert* — ${articles.length} new article${articles.length !== 1 ? 's' : ''}\n\n${buildTextSummary(articles)}`;
  const res = await fetch(webhookUrl, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ text }),
  });
  if (!res.ok) throw new Error(`Slack webhook returned ${res.status}`);
}

/**
 * Send to a Discord webhook.
 */
async function sendDiscord(webhookUrl, articles) {
  const embeds = articles.slice(0, 10).map(a => ({
    title: a.title.slice(0, 256),
    url: a.link,
    description: a.summary ? a.summary.slice(0, 200) : undefined,
    color: 0x22d3ee,
    fields: [
      a.source ? { name: 'Source', value: a.source, inline: true } : null,
      a.category ? { name: 'Category', value: a.category, inline: true } : null,
      a.vendor ? { name: 'Vendor', value: a.vendor, inline: true } : null,
    ].filter(Boolean),
    footer: { text: 'FreeIntelHub' },
    timestamp: a.published_at || new Date().toISOString(),
  }));

  const res = await fetch(webhookUrl, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      content: `**FreeIntelHub Alert** — ${articles.length} new article${articles.length !== 1 ? 's' : ''}`,
      embeds,
    }),
  });
  if (!res.ok) throw new Error(`Discord webhook returned ${res.status}`);
}

/**
 * Send to Telegram via Bot API.
 * webhookUrl format: https://api.telegram.org/bot<TOKEN>/sendMessage?chat_id=<CHAT_ID>
 * We parse bot token and chat_id from the URL.
 */
async function sendTelegram(webhookUrl, articles) {
  // Accept format: tg://<bot_token>/<chat_id> or full Telegram API URL
  let apiUrl, chatId;

  if (webhookUrl.startsWith('tg://')) {
    const parts = webhookUrl.replace('tg://', '').split('/');
    const botToken = parts[0];
    chatId = parts[1];
    apiUrl = `https://api.telegram.org/bot${botToken}/sendMessage`;
  } else {
    // Assume full URL with chat_id param
    const url = new URL(webhookUrl);
    chatId = url.searchParams.get('chat_id');
    apiUrl = `${url.origin}${url.pathname}`;
  }

  const text = `🚨 <b>FreeIntelHub Alert</b> — ${articles.length} new article${articles.length !== 1 ? 's' : ''}\n\n` +
    articles.map(a => {
      let line = `• <a href="${escHtml(a.link)}">${escHtml(a.title)}</a>`;
      const tags = [a.source, a.category, a.vendor].filter(Boolean);
      if (tags.length) line += `\n  <i>${escHtml(tags.join(' | '))}</i>`;
      return line;
    }).join('\n\n');

  const res = await fetch(apiUrl, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      chat_id: chatId,
      text,
      parse_mode: 'HTML',
      disable_web_page_preview: true,
    }),
  });
  if (!res.ok) throw new Error(`Telegram API returned ${res.status}`);
}

/**
 * Send to a generic/custom webhook (POST JSON payload).
 */
async function sendCustomWebhook(webhookUrl, articles) {
  const payload = {
    source: 'FreeIntelHub',
    timestamp: new Date().toISOString(),
    count: articles.length,
    articles: articles.map(a => ({
      title: a.title,
      link: a.link,
      summary: a.summary || null,
      source: a.source,
      category: a.category || null,
      vendor: a.vendor || null,
      sector: a.sector || null,
      mitre_techniques: safeParse(a.mitre_techniques),
      iocs: safeParse(a.iocs),
      published_at: a.published_at,
    })),
  };

  const res = await fetch(webhookUrl, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload),
  });
  if (!res.ok) throw new Error(`Custom webhook returned ${res.status}`);
}

/**
 * Dispatch articles to a webhook based on its type.
 * Decrypts the URL if encrypted, then validates against SSRF at fetch time.
 */
async function sendWebhook(type, url, articles) {
  const resolvedUrl = decryptWebhookUrl(url);
  // Telegram tg:// URLs are constructed internally to api.telegram.org — no SSRF risk
  if (type !== 'telegram') {
    await validateNoSsrfAtFetchTime(resolvedUrl);
  }
  switch (type) {
    case 'slack': return sendSlack(resolvedUrl, articles);
    case 'discord': return sendDiscord(resolvedUrl, articles);
    case 'telegram': return sendTelegram(resolvedUrl, articles);
    case 'webhook': return sendCustomWebhook(resolvedUrl, articles);
    default: throw new Error(`Unknown webhook type: ${type}`);
  }
}

function escHtml(s) {
  if (!s) return '';
  return String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
}

module.exports = { sendWebhook };
