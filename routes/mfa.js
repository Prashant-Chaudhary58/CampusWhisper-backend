const express = require('express');
const router = express.Router();
const speakeasy = require('speakeasy');
const qrcode = require('qrcode');
const User = require('../models/User');
const { requireAuth } = require('../middleware/auth');
const { logSecurityEvent } = require('../utils/logger');

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
 * @desc    Verify TOTP token to activate MFA (Prevent user lockouts)
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

    user.mfaEnabled = true;
    await user.save();

    req.session.mfaVerified = true;

    logSecurityEvent(userId, 'MFA_ACTIVATION', 'SUCCESS', ip, 'MFA active');

    res.json({ message: 'MFA activated successfully' });
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
    await user.save();

    logSecurityEvent(userId, 'MFA_DISABLE', 'SUCCESS', ip, 'MFA deactivated');

    res.json({ message: 'MFA deactivated successfully' });
  } catch (error) {
    logSecurityEvent(userId, 'MFA_DISABLE', 'ERROR', ip, error.message);
    res.status(500).json({ error: 'Server error disabling MFA' });
  }
});

module.exports = router;
