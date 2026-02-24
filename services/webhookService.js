/**
 * Webhook Service — Sends alerts to Slack, Discord, Telegram, and custom webhooks.
 */

const BASE_URL = process.env.BASE_URL || 'http://localhost:3000';

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
 */
async function sendWebhook(type, url, articles) {
  switch (type) {
    case 'slack': return sendSlack(url, articles);
    case 'discord': return sendDiscord(url, articles);
    case 'telegram': return sendTelegram(url, articles);
    case 'webhook': return sendCustomWebhook(url, articles);
    default: throw new Error(`Unknown webhook type: ${type}`);
  }
}

function escHtml(s) {
  if (!s) return '';
  return String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
}

module.exports = { sendWebhook };
