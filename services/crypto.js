/**
 * Shared cryptographic utilities.
 * - Token hashing (SHA-256) for safe DB storage of subscriber tokens
 * - Webhook URL encryption/decryption (AES-256-GCM)
 */

const crypto = require('crypto');

// ---------------------------------------------------------------------------
// Token hashing
// ---------------------------------------------------------------------------

/**
 * Hash a raw token with SHA-256 for safe storage.
 * The user retains the plaintext; the DB stores only the hash.
 */
function hashToken(token) {
  return crypto.createHash('sha256').update(token).digest('hex');
}

// ---------------------------------------------------------------------------
// Webhook URL encryption (AES-256-GCM)
// ---------------------------------------------------------------------------

const WEBHOOK_ENC_KEY_HEX = process.env.WEBHOOK_ENCRYPTION_KEY;

function getEncKey() {
  if (!WEBHOOK_ENC_KEY_HEX) return null;
  if (WEBHOOK_ENC_KEY_HEX.length !== 64) {
    console.warn('[Crypto] WEBHOOK_ENCRYPTION_KEY must be 64 hex chars (32 bytes). Webhook encryption disabled.');
    return null;
  }
  return Buffer.from(WEBHOOK_ENC_KEY_HEX, 'hex');
}

/**
 * Encrypt a webhook URL using AES-256-GCM.
 * Returns the plaintext unchanged if WEBHOOK_ENCRYPTION_KEY is not set.
 * Format: enc:<iv_hex>:<tag_hex>:<ciphertext_hex>
 */
function encryptWebhookUrl(plaintext) {
  const key = getEncKey();
  if (!key) return plaintext;
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
  let enc = cipher.update(plaintext, 'utf8', 'hex');
  enc += cipher.final('hex');
  const tag = cipher.getAuthTag().toString('hex');
  return `enc:${iv.toString('hex')}:${tag}:${enc}`;
}

/**
 * Decrypt a webhook URL encrypted by encryptWebhookUrl.
 * Returns the value unchanged if it is not in encrypted format.
 */
function decryptWebhookUrl(stored) {
  if (!stored || !stored.startsWith('enc:')) return stored;
  const key = getEncKey();
  if (!key) return stored;
  try {
    const parts = stored.split(':');
    const iv = Buffer.from(parts[1], 'hex');
    const tag = Buffer.from(parts[2], 'hex');
    const encHex = parts[3];
    const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv);
    decipher.setAuthTag(tag);
    let dec = decipher.update(encHex, 'hex', 'utf8');
    dec += decipher.final('utf8');
    return dec;
  } catch (_) {
    return stored;
  }
}

module.exports = { hashToken, encryptWebhookUrl, decryptWebhookUrl };
