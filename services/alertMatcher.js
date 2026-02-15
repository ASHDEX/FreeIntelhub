const db = require('../db');
const { sendAlert } = require('./emailService');
const { sendWebhook } = require('./webhookService');

// Prepared statements
const getVerifiedSubscribersWithRules = db.prepare(`
  SELECT s.id, s.email, s.token FROM subscribers s
  WHERE s.verified = 1
  AND EXISTS (SELECT 1 FROM alert_rules WHERE subscriber_id = s.id)
`);

const getRulesForSubscriber = db.prepare(`
  SELECT rule_type, rule_value FROM alert_rules WHERE subscriber_id = ?
`);

const getWebhooksForSubscriber = db.prepare(`
  SELECT webhook_type, webhook_url FROM webhooks WHERE subscriber_id = ?
`);

const insertSentAlert = db.prepare(`
  INSERT OR IGNORE INTO sent_alerts (subscriber_id, article_id) VALUES (?, ?)
`);

const checkSentAlert = db.prepare(`
  SELECT 1 FROM sent_alerts WHERE subscriber_id = ? AND article_id = ?
`);

/**
 * Check if an article matches a subscriber's rules.
 * Returns true if any rule matches.
 */
function articleMatchesRules(article, rules) {
  for (const rule of rules) {
    const val = rule.rule_value.toLowerCase();
    switch (rule.rule_type) {
      case 'vendor':
        if (article.vendor && article.vendor.toLowerCase() === val) return true;
        break;
      case 'category':
        if (article.category && article.category.toLowerCase() === val) return true;
        break;
      case 'sector':
        if (article.sector && article.sector.toLowerCase() === val) return true;
        break;
      case 'keyword': {
        const titleMatch = article.title && article.title.toLowerCase().includes(val);
        const summaryMatch = article.summary && article.summary.toLowerCase().includes(val);
        const vendorMatch = article.vendor && article.vendor.toLowerCase().includes(val);
        if (titleMatch || summaryMatch || vendorMatch) return true;
        break;
      }
    }
  }
  return false;
}

/**
 * Process newly inserted articles against all subscriber rules.
 * Batches matched articles per subscriber and sends email + webhook notifications.
 */
async function processNewArticles(articles) {
  if (!articles || articles.length === 0) return;

  const subscribers = getVerifiedSubscribersWithRules.all();
  if (subscribers.length === 0) return;

  let totalEmailSent = 0;
  let totalWebhookSent = 0;

  for (const subscriber of subscribers) {
    const rules = getRulesForSubscriber.all(subscriber.id);
    const matched = [];

    for (const article of articles) {
      if (!article.id) continue;
      // Skip if already notified
      if (checkSentAlert.get(subscriber.id, article.id)) continue;
      if (articleMatchesRules(article, rules)) {
        matched.push(article);
      }
    }

    if (matched.length === 0) continue;

    // Record sent alerts (even if email fails, to avoid spam on retry)
    const markSent = db.transaction(() => {
      for (const a of matched) {
        insertSentAlert.run(subscriber.id, a.id);
      }
    });
    markSent();

    // Send email alert
    const sent = await sendAlert(subscriber, matched);
    if (sent) totalEmailSent++;

    // Send webhook alerts
    const webhooks = getWebhooksForSubscriber.all(subscriber.id);
    for (const wh of webhooks) {
      try {
        await sendWebhook(wh.webhook_type, wh.webhook_url, matched);
        totalWebhookSent++;
      } catch (err) {
        console.error(`[Webhook] Failed ${wh.webhook_type} for subscriber ${subscriber.id}: ${err.message}`);
      }
    }
  }

  if (totalEmailSent > 0) {
    console.log(`[Alerts] Sent alert emails to ${totalEmailSent} subscriber(s)`);
  }
  if (totalWebhookSent > 0) {
    console.log(`[Alerts] Sent ${totalWebhookSent} webhook notification(s)`);
  }
}

module.exports = { processNewArticles, articleMatchesRules };
