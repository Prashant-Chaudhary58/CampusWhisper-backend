const express = require('express');
const router = express.Router();
const speakeasy = require('speakeasy');
const qrcode = require('qrcode');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const User = require('../models/User');
const { requireAuth } = require('../middleware/auth');
const { logSecurityEvent } = require('../utils/logger');

// Ensure log directory exists for mock email logs
const logDir = path.join(__dirname, '../logs');
if (!fs.existsSync(logDir)) {
  fs.mkdirSync(logDir, { recursive: true });
}
const emailInboxFile = path.join(logDir, 'email_inbox.log');

/**
 * @route   POST /api/mfa/setup
 * @desc    Generate TOTP secret and QR code for MFA enrollment
 */
router.post('/setup', requireAuth, async (req, res) => {
  const ip = req.ip;
  const userId = req.session.userId;
  try {
    const user = await User.findById(userId);
    if (!user) {
      logSecurityEvent(userId, 'MFA_SETUP', 'FAILURE', ip, 'User not found');
      return res.status(404).json({ error: 'User not found' });
    }

    if (user.mfaEnabled) {
      logSecurityEvent(userId, 'MFA_SETUP', 'FAILURE', ip, 'MFA already enabled');
      return res.status(400).json({ error: 'MFA is already enabled' });
    }

    const secret = speakeasy.generateSecret({
      name: `CampusWhisper (${user.email})`
    });

    user.mfaSecret = secret.base32;
    await user.save();

    logSecurityEvent(userId, 'MFA_SETUP_INITIALIZED', 'SUCCESS', ip, 'TOTP secret generated');

    qrcode.toDataURL(secret.otpauth_url, (err, dataUrl) => {
      if (err) {
        logSecurityEvent(userId, 'MFA_SETUP_QR', 'FAILURE', ip, err.message);
        return res.status(500).json({ error: 'Error generating QR code' });
      }
      res.json({
        secret: secret.base32,
        qrCode: dataUrl
      });
    });
  } catch (error) {
    logSecurityEvent(userId, 'MFA_SETUP', 'ERROR', ip, error.message);
    res.status(500).json({ error: 'Server error setting up MFA' });
  }
});

/**
 * @route   POST /api/mfa/verify
 * @desc    Verify TOTP token to activate MFA & generate backup recovery codes
 */
router.post('/verify', requireAuth, async (req, res) => {
  const ip = req.ip;
  const userId = req.session.userId;
  try {
    const { token } = req.body;
    if (!token) {
      logSecurityEvent(userId, 'MFA_ACTIVATION', 'FAILURE', ip, 'Missing code token');
      return res.status(400).json({ error: 'Verification token is required' });
    }

    const user = await User.findById(userId);
    if (!user || !user.mfaSecret) {
      logSecurityEvent(userId, 'MFA_ACTIVATION', 'FAILURE', ip, 'MFA not initialized');
      return res.status(400).json({ error: 'MFA setup has not been initialized' });
    }

    const verified = speakeasy.totp.verify({
      secret: user.mfaSecret,
      encoding: 'base32',
      token,
      window: 1
    });

    if (!verified) {
      logSecurityEvent(userId, 'MFA_ACTIVATION', 'FAILURE', ip, 'Invalid TOTP token submitted');
      return res.status(400).json({ error: 'Invalid verification token' });
    }

    // Enable MFA
    user.mfaEnabled = true;

    // Generate 5 single-use backup recovery codes
    const plainBackupCodes = [];
    const hashedBackupCodes = [];

    for (let i = 0; i < 5; i++) {
      // Create random 10 character code formatted like "ABCD-1234"
      const r1 = crypto.randomBytes(2).toString('hex').toUpperCase();
      const r2 = crypto.randomBytes(2).toString('hex').toUpperCase();
      const plainCode = `${r1}-${r2}`;
      plainBackupCodes.push(plainCode);

      const hashed = crypto.createHash('sha256').update(plainCode).digest('hex');
      hashedBackupCodes.push(hashed);
    }

    user.mfaBackupCodes = hashedBackupCodes;
    await user.save();

    req.session.mfaVerified = true;

    logSecurityEvent(userId, 'MFA_ACTIVATION', 'SUCCESS', ip, 'MFA active, backup codes generated');

    res.json({ 
      message: 'MFA activated successfully',
      backupCodes: plainBackupCodes
    });
  } catch (error) {
    logSecurityEvent(userId, 'MFA_ACTIVATION', 'ERROR', ip, error.message);
    res.status(500).json({ error: 'Server error verifying MFA' });
  }
});

/**
 * @route   POST /api/mfa/login-verify
 * @desc    Verify TOTP token during the login flow
 */
router.post('/login-verify', async (req, res) => {
  const ip = req.ip;
  const userId = req.session.userId || 'anonymous';
  try {
    const { token } = req.body;
    if (!token) {
      logSecurityEvent(userId, 'MFA_LOGIN_VERIFY', 'FAILURE', ip, 'Missing token');
      return res.status(400).json({ error: 'Verification token is required' });
    }

    if (!req.session.userId) {
      logSecurityEvent(userId, 'MFA_LOGIN_VERIFY', 'FAILURE', ip, 'No userId in session context');
      return res.status(401).json({ error: 'Session expired or not found. Please login again.' });
    }

    const user = await User.findById(req.session.userId);
    if (!user || !user.mfaEnabled || !user.mfaSecret) {
      logSecurityEvent(req.session.userId, 'MFA_LOGIN_VERIFY', 'FAILURE', ip, 'MFA not enabled');
      return res.status(400).json({ error: 'MFA is not enabled for this account' });
    }

    const verified = speakeasy.totp.verify({
      secret: user.mfaSecret,
      encoding: 'base32',
      token,
      window: 1
    });

    if (!verified) {
      logSecurityEvent(user._id, 'MFA_LOGIN_VERIFY', 'FAILURE', ip, 'Incorrect token');
      return res.status(400).json({ error: 'Invalid verification token' });
    }

    req.session.mfaVerified = true;

    logSecurityEvent(user._id, 'MFA_LOGIN_VERIFY', 'SUCCESS', ip, 'MFA challenge passed');

    res.json({
      message: 'Login verification successful',
      user: {
        id: user._id,
        email: user.email,
        role: user.role,
        mfaEnabled: user.mfaEnabled
      }
    });
  } catch (error) {
    logSecurityEvent(userId, 'MFA_LOGIN_VERIFY', 'ERROR', ip, error.message);
    res.status(500).json({ error: 'Server error during MFA login verification' });
  }
});

/**
 * @route   POST /api/mfa/backup-verify
 * @desc    Verify single-use backup recovery code during login
 */
router.post('/backup-verify', async (req, res) => {
  const ip = req.ip;
  const userId = req.session.userId || 'anonymous';
  try {
    const { code } = req.body;
    if (!code) {
      logSecurityEvent(userId, 'MFA_BACKUP_VERIFY', 'FAILURE', ip, 'Missing backup code');
      return res.status(400).json({ error: 'Backup code is required' });
    }

    if (!req.session.userId) {
      return res.status(401).json({ error: 'Session expired. Please login again.' });
    }

    const user = await User.findById(req.session.userId);
    if (!user || !user.mfaEnabled) {
      return res.status(400).json({ error: 'MFA is not enabled' });
    }

    // Hash user-submitted code to match database
    const submittedHash = crypto.createHash('sha256').update(code.trim().toUpperCase()).digest('hex');

    const codeIndex = user.mfaBackupCodes.indexOf(submittedHash);
    if (codeIndex === -1) {
      logSecurityEvent(user._id, 'MFA_BACKUP_VERIFY', 'FAILURE', ip, 'Invalid backup code attempted');
      return res.status(400).json({ error: 'Invalid backup recovery code' });
    }

    // Remove the used code (Enforce Single-Use property - CWE-307)
    user.mfaBackupCodes.splice(codeIndex, 1);
    await user.save();

    req.session.mfaVerified = true;
    logSecurityEvent(user._id, 'MFA_BACKUP_VERIFY', 'SUCCESS', ip, 'Backup recovery code utilized');

    res.json({
      message: 'Backup code accepted. Login successful.',
      user: {
        id: user._id,
        email: user.email,
        role: user.role,
        mfaEnabled: user.mfaEnabled
      }
    });
  } catch (error) {
    logSecurityEvent(userId, 'MFA_BACKUP_VERIFY', 'ERROR', ip, error.message);
    res.status(500).json({ error: 'Server error during backup code verification' });
  }
});

/**
 * @route   POST /api/mfa/email-request
 * @desc    Request a 6-digit MFA verification code sent to student email
 */
router.post('/email-request', async (req, res) => {
  const ip = req.ip;
  if (!req.session.userId) {
    return res.status(401).json({ error: 'Session expired. Please login again.' });
  }

  try {
    const user = await User.findById(req.session.userId);
    if (!user || !user.mfaEnabled) {
      return res.status(400).json({ error: 'MFA is not configured for this account' });
    }

    // Generate secure 6-digit PIN
    const rawPin = Math.floor(100000 + Math.random() * 900000).toString();
    const hashedPin = crypto.createHash('sha256').update(rawPin).digest('hex');

    user.mfaEmailCode = hashedPin;
    user.mfaEmailCodeExpires = Date.now() + 5 * 60 * 1000; // 5 minute validity
    await user.save();

    // Log the mock email sending details (Mock SMTP integration for coursework verification)
    const emailLogLine = `[${new Date().toISOString()}] [SMTP TO:${user.email}] SUBJECT: CampusWhisper Login PIN Code. Your secure MFA verification code is: ${rawPin} (Expires in 5 minutes)\n`;
    fs.appendFileSync(emailInboxFile, emailLogLine);

    logSecurityEvent(user._id, 'MFA_EMAIL_REQUEST', 'SUCCESS', ip, 'MFA Email pin dispatched to mock log');
    
    res.json({ message: 'A 6-digit verification code has been dispatched to your email.' });
  } catch (error) {
    logSecurityEvent(req.session.userId, 'MFA_EMAIL_REQUEST', 'ERROR', ip, error.message);
    res.status(500).json({ error: 'Server error triggering Email code' });
  }
});

/**
 * @route   POST /api/mfa/email-verify
 * @desc    Verify the email pin to authenticate login session
 */
router.post('/email-verify', async (req, res) => {
  const ip = req.ip;
  const userId = req.session.userId || 'anonymous';
  try {
    const { token } = req.body;
    if (!token) {
      return res.status(400).json({ error: 'Email verification token is required' });
    }

    if (!req.session.userId) {
      return res.status(401).json({ error: 'Session context missing' });
    }

    const user = await User.findById(req.session.userId);
    if (!user || !user.mfaEnabled || !user.mfaEmailCode) {
      return res.status(400).json({ error: 'Email verification not active or not initialized' });
    }

    // Check expiry
    if (user.mfaEmailCodeExpires < Date.now()) {
      logSecurityEvent(user._id, 'MFA_EMAIL_VERIFY', 'FAILURE', ip, 'Token expired');
      return res.status(400).json({ error: 'Email PIN has expired. Please request a new code.' });
    }

    // Validate token hash
    const submittedHash = crypto.createHash('sha256').update(token.trim()).digest('hex');
    if (submittedHash !== user.mfaEmailCode) {
      logSecurityEvent(user._id, 'MFA_EMAIL_VERIFY', 'FAILURE', ip, 'Incorrect token input');
      return res.status(400).json({ error: 'Invalid verification token' });
    }

    // Clean verification codes on success
    user.mfaEmailCode = null;
    user.mfaEmailCodeExpires = null;
    await user.save();

    req.session.mfaVerified = true;
    logSecurityEvent(user._id, 'MFA_EMAIL_VERIFY', 'SUCCESS', ip, 'Email PIN code accepted');

    res.json({
      message: 'Login successful via Email MFA',
      user: {
        id: user._id,
        email: user.email,
        role: user.role,
        mfaEnabled: user.mfaEnabled
      }
    });
  } catch (error) {
    logSecurityEvent(userId, 'MFA_EMAIL_VERIFY', 'ERROR', ip, error.message);
    res.status(500).json({ error: 'Server error verifying Email PIN' });
  }
});

/**
 * @route   POST /api/mfa/disable
 * @desc    Disable MFA for user's account
 */
router.post('/disable', requireAuth, async (req, res) => {
  const ip = req.ip;
  const userId = req.session.userId;
  try {
    const { token } = req.body;
    if (!token) {
      logSecurityEvent(userId, 'MFA_DISABLE', 'FAILURE', ip, 'Missing verification token');
      return res.status(400).json({ error: 'Verification token is required to disable MFA' });
    }

    const user = await User.findById(userId);
    if (!user || !user.mfaEnabled) {
      logSecurityEvent(userId, 'MFA_DISABLE', 'FAILURE', ip, 'MFA already disabled');
      return res.status(400).json({ error: 'MFA is not enabled' });
    }

    const verified = speakeasy.totp.verify({
      secret: user.mfaSecret,
      encoding: 'base32',
      token,
      window: 1
    });

    if (!verified) {
      logSecurityEvent(userId, 'MFA_DISABLE', 'FAILURE', ip, 'Incorrect token');
      return res.status(400).json({ error: 'Invalid verification token' });
    }

    user.mfaEnabled = false;
    user.mfaSecret = null;
    user.mfaBackupCodes = [];
    await user.save();

    logSecurityEvent(userId, 'MFA_DISABLE', 'SUCCESS', ip, 'MFA deactivated');

    res.json({ message: 'MFA deactivated successfully' });
  } catch (error) {
    logSecurityEvent(userId, 'MFA_DISABLE', 'ERROR', ip, error.message);
    res.status(500).json({ error: 'Server error disabling MFA' });
  }
});

module.exports = router;
