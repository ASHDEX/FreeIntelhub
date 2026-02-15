const nodemailer = require('nodemailer');

const SMTP_HOST = process.env.SMTP_HOST || '';
const SMTP_PORT = parseInt(process.env.SMTP_PORT, 10) || 587;
const SMTP_USER = process.env.SMTP_USER || '';
const SMTP_PASS = process.env.SMTP_PASS || '';
const FROM_EMAIL = process.env.FROM_EMAIL || 'alerts@freeintelhub.com';
const BASE_URL = process.env.BASE_URL || 'http://localhost:3000';

let transporter = null;

function getTransporter() {
  if (transporter) return transporter;
  if (!SMTP_HOST) return null;
  transporter = nodemailer.createTransport({
    host: SMTP_HOST,
    port: SMTP_PORT,
    secure: SMTP_PORT === 465,
    auth: { user: SMTP_USER, pass: SMTP_PASS },
  });
  return transporter;
}

function isConfigured() {
  return Boolean(SMTP_HOST && SMTP_USER && SMTP_PASS);
}

// --- HTML Templates ---

function layoutWrap(title, body) {
  return `<!DOCTYPE html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<style>
body{margin:0;padding:0;background:#09090b;color:#fafafa;font-family:'Segoe UI',Roboto,sans-serif}
.wrap{max-width:600px;margin:0 auto;padding:24px 16px}
.header{text-align:center;padding:16px 0;border-bottom:1px solid rgba(255,255,255,0.06);margin-bottom:24px}
.logo{font-size:18px;font-weight:700;color:#fafafa;text-decoration:none}
.logo span{color:#22d3ee}
h1{font-size:20px;font-weight:700;margin:0 0 8px}
h2{font-size:16px;font-weight:600;margin:20px 0 10px;color:#a1a1aa}
.card{background:#111113;border:1px solid rgba(255,255,255,0.06);border-radius:8px;padding:12px 16px;margin-bottom:8px}
.card h3{margin:0 0 4px;font-size:14px}
.card h3 a{color:#fafafa;text-decoration:none}
.card h3 a:hover{color:#22d3ee}
.badge{display:inline-block;padding:2px 8px;border-radius:100px;font-size:11px;font-weight:500}
.badge-source{background:rgba(59,130,246,0.1);color:#60a5fa}
.badge-category{background:rgba(167,139,250,0.1);color:#a78bfa}
.badge-vendor{background:rgba(34,211,238,0.1);color:#22d3ee}
.meta{font-size:12px;color:#71717a;margin-bottom:6px}
.summary{font-size:13px;color:#a1a1aa;line-height:1.5}
.btn{display:inline-block;padding:10px 24px;background:#22d3ee;color:#09090b;border-radius:8px;font-weight:600;font-size:14px;text-decoration:none;margin:16px 0}
.footer{text-align:center;padding:20px 0;margin-top:24px;border-top:1px solid rgba(255,255,255,0.06);font-size:12px;color:#71717a}
.footer a{color:#22d3ee}
.muted{color:#71717a;font-size:13px}
</style></head><body>
<div class="wrap">
<div class="header"><a href="${BASE_URL}" class="logo">Free<span>Intel</span>Hub</a></div>
${body}
<div class="footer">
<p><a href="${BASE_URL}">FreeIntelHub</a> &mdash; Open-source threat intelligence</p>
<p style="margin-top:8px">${title === 'Verify' ? '' : '<a href="{{unsubscribe_url}}">Unsubscribe</a>'}</p>
</div>
</div></body></html>`;
}

function verificationEmail(token) {
  const url = `${BASE_URL}/alerts/verify?token=${token}`;
  const body = `
<h1>Verify your email</h1>
<p class="muted">Click the button below to confirm your alert subscription on FreeIntelHub.</p>
<div style="text-align:center"><a href="${url}" class="btn">Verify Email</a></div>
<p class="muted">Or copy this link: ${url}</p>`;
  return layoutWrap('Verify', body).replace('{{unsubscribe_url}}', '');
}

function alertEmail(subscriber, articles) {
  const unsubUrl = `${BASE_URL}/alerts/unsubscribe?token=${subscriber.token}`;
  const manageUrl = `${BASE_URL}/alerts?token=${subscriber.token}`;
  const cards = articles.map(a => `
<div class="card">
  <div class="meta">
    <span class="badge badge-source">${esc(a.source)}</span>
    ${a.category ? `<span class="badge badge-category">${esc(a.category)}</span>` : ''}
    ${a.vendor ? `<span class="badge badge-vendor">${esc(a.vendor)}</span>` : ''}
  </div>
  <h3><a href="${esc(a.link)}">${esc(a.title)}</a></h3>
  ${a.summary ? `<p class="summary">${esc(a.summary)}</p>` : ''}
</div>`).join('');
  const body = `
<h1>Alert: ${articles.length} new article${articles.length !== 1 ? 's' : ''} match your rules</h1>
<p class="muted">The following articles matched your alert subscriptions.</p>
${cards}
<div style="text-align:center;margin-top:16px"><a href="${manageUrl}" class="btn">Manage Alerts</a></div>`;
  return layoutWrap('Alert', body).replace('{{unsubscribe_url}}', unsubUrl);
}

function newsletterEmail(subscriber, articlesBySection) {
  const unsubUrl = `${BASE_URL}/alerts/unsubscribe?token=${subscriber.token}`;
  const manageUrl = `${BASE_URL}/alerts?token=${subscriber.token}`;
  let sections = '';
  for (const [title, articles] of Object.entries(articlesBySection)) {
    if (!articles.length) continue;
    const cards = articles.map(a => `
<div class="card">
  <div class="meta">
    <span class="badge badge-source">${esc(a.source)}</span>
    ${a.category ? `<span class="badge badge-category">${esc(a.category)}</span>` : ''}
  </div>
  <h3><a href="${esc(a.link)}">${esc(a.title)}</a></h3>
  ${a.summary ? `<p class="summary">${esc(a.summary)}</p>` : ''}
</div>`).join('');
    sections += `<h2>${esc(title)}</h2>${cards}`;
  }
  const today = new Date().toLocaleDateString('en-US', { weekday: 'long', month: 'long', day: 'numeric', year: 'numeric' });
  const body = `
<h1>Daily Digest</h1>
<p class="muted">${today} &mdash; Top stories from the last 24 hours</p>
${sections || '<p class="muted">No new articles in the last 24 hours.</p>'}
<div style="text-align:center;margin-top:16px"><a href="${manageUrl}" class="btn">Manage Alerts</a></div>`;
  return layoutWrap('Newsletter', body).replace('{{unsubscribe_url}}', unsubUrl);
}

function esc(s) {
  if (!s) return '';
  return String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
}

// --- Send functions ---

async function sendVerification(email, token) {
  const t = getTransporter();
  if (!t) { console.log('[Email] SMTP not configured — skipping verification email'); return false; }
  try {
    await t.sendMail({
      from: FROM_EMAIL,
      to: email,
      subject: 'Verify your FreeIntelHub subscription',
      html: verificationEmail(token),
    });
    console.log(`[Email] Verification sent to ${email}`);
    return true;
  } catch (err) {
    console.error(`[Email] Failed to send verification to ${email}: ${err.message}`);
    return false;
  }
}

async function sendAlert(subscriber, articles) {
  const t = getTransporter();
  if (!t) return false;
  try {
    await t.sendMail({
      from: FROM_EMAIL,
      to: subscriber.email,
      subject: `FreeIntelHub Alert: ${articles.length} new article${articles.length !== 1 ? 's' : ''} matched`,
      html: alertEmail(subscriber, articles),
    });
    console.log(`[Email] Alert sent to ${subscriber.email} (${articles.length} articles)`);
    return true;
  } catch (err) {
    console.error(`[Email] Failed to send alert to ${subscriber.email}: ${err.message}`);
    return false;
  }
}

async function sendNewsletter(subscriber, articlesBySection) {
  const t = getTransporter();
  if (!t) return false;
  try {
    await t.sendMail({
      from: FROM_EMAIL,
      to: subscriber.email,
      subject: `FreeIntelHub Daily Digest — ${new Date().toLocaleDateString('en-US', { month: 'short', day: 'numeric' })}`,
      html: newsletterEmail(subscriber, articlesBySection),
    });
    console.log(`[Email] Newsletter sent to ${subscriber.email}`);
    return true;
  } catch (err) {
    console.error(`[Email] Failed to send newsletter to ${subscriber.email}: ${err.message}`);
    return false;
  }
}

module.exports = { sendVerification, sendAlert, sendNewsletter, isConfigured };
