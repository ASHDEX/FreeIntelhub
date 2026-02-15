const cron = require('node-cron');
const db = require('../db');
const { sendNewsletter, isConfigured } = require('./emailService');

const getNewsletterSubscribers = db.prepare(`
  SELECT * FROM subscribers WHERE daily_newsletter = 1 AND verified = 1
`);

const getArticlesLast24h = db.prepare(`
  SELECT * FROM articles
  WHERE created_at >= datetime('now', '-1 day')
  ORDER BY published_at DESC
`);

const getTopByCategory = db.prepare(`
  SELECT * FROM articles
  WHERE created_at >= datetime('now', '-1 day') AND category = ?
  ORDER BY published_at DESC LIMIT 5
`);

/**
 * Send daily newsletter to all verified subscribers who opted in.
 */
async function sendDailyNewsletter() {
  if (!isConfigured()) {
    console.log('[Newsletter] SMTP not configured — skipping');
    return;
  }

  const subscribers = getNewsletterSubscribers.all();
  if (subscribers.length === 0) {
    console.log('[Newsletter] No subscribers — skipping');
    return;
  }

  const allRecent = getArticlesLast24h.all();
  if (allRecent.length === 0) {
    console.log('[Newsletter] No articles in last 24h — skipping');
    return;
  }

  // Group articles into sections
  const sections = {};

  // Top stories (latest 10)
  sections['Top Stories'] = allRecent.slice(0, 10);

  // Data breaches
  const breaches = getTopByCategory.all('Data Breach');
  if (breaches.length > 0) sections['Data Breaches'] = breaches;

  // Zero-days
  const zerodays = getTopByCategory.all('Zero-Day');
  if (zerodays.length > 0) sections['Zero-Day Vulnerabilities'] = zerodays;

  // Ransomware
  const ransomware = getTopByCategory.all('Ransomware');
  if (ransomware.length > 0) sections['Ransomware'] = ransomware;

  let sentCount = 0;
  for (const subscriber of subscribers) {
    const sent = await sendNewsletter(subscriber, sections);
    if (sent) sentCount++;
  }

  console.log(`[Newsletter] Sent to ${sentCount}/${subscribers.length} subscribers`);
}

/**
 * Start the daily newsletter cron job.
 * Runs at 7:00 AM UTC every day.
 */
function startNewsletterCron() {
  const schedule = process.env.NEWSLETTER_CRON || '0 7 * * *';
  cron.schedule(schedule, () => {
    console.log('[Newsletter] Running daily digest...');
    sendDailyNewsletter().catch(err => {
      console.error(`[Newsletter] Error: ${err.message}`);
    });
  });
  console.log(`[Newsletter] Cron scheduled: ${schedule}`);
}

module.exports = { startNewsletterCron, sendDailyNewsletter };
