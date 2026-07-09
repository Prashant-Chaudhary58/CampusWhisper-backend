const crypto = require('crypto');

const ALGORITHM = 'aes-256-gcm';
// ENCRYPTION_KEY should be 32 bytes (64 hex characters)
const KEY = Buffer.from(process.env.ENCRYPTION_KEY, 'hex');

if (KEY.length !== 32) {
  throw new Error('Invalid ENCRYPTION_KEY. Must be a 32-byte hex string (64 characters).');
}

/**
 * Encrypt plain text using AES-256-GCM
 * @param {string} text - Plain text to encrypt
 * @returns {string} - Combined string of iv:authTag:ciphertext
 */
const encrypt = (text) => {
  if (!text) return '';
  
  // 12-byte initialization vector is standard for AES-GCM to prevent replay/dictionary attacks
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv(ALGORITHM, KEY, iv);
  
  let encrypted = cipher.update(text, 'utf8', 'hex');
  encrypted += cipher.final('hex');
  
  const authTag = cipher.getAuthTag().toString('hex');
  
  return `${iv.toString('hex')}:${authTag}:${encrypted}`;
};

/**
 * Decrypt cipher text using AES-256-GCM
 * @param {string} encryptedText - Encrypted string (iv:authTag:ciphertext)
 * @returns {string} - Decrypted plain text
 */
const decrypt = (encryptedText) => {
  if (!encryptedText) return '';
  
  const parts = encryptedText.split(':');
  if (parts.length !== 3) {
    throw new Error('Invalid ciphertext format');
  }
  
  const iv = Buffer.from(parts[0], 'hex');
  const authTag = Buffer.from(parts[1], 'hex');
  const encrypted = parts[2];
  
  const decipher = crypto.createDecipheriv(ALGORITHM, KEY, iv);
  decipher.setAuthTag(authTag);
  
  let decrypted = decipher.update(encrypted, 'hex', 'utf8');
  decrypted += decipher.final('utf8');
  
  return decrypted;
};

module.exports = {
  encrypt,
  decrypt
};
