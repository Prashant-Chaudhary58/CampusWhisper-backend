const express = require('express');
const router = express.Router();
const User = require('../models/User');
const { authLimiter } = require('../middleware/rateLimiter');
const { logSecurityEvent } = require('../utils/logger');

// Password complexity regex (Min 12 chars, 1 upper, 1 lower, 1 digit, 1 special)
const PASSWORD_REGEX = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{12,}$/;
// Institutional email domain validator
const EMAIL_REGEX = /^\w+([.-]?\w+)*@university\.edu$/;

/**
 * @route   POST /api/auth/register
 * @desc    Register a new reporter user
 */
router.post('/register', authLimiter, async (req, res) => {
  const ip = req.ip;
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      logSecurityEvent('unauthenticated', 'USER_REGISTRATION', 'FAILURE', ip, 'Missing email or password');
      return res.status(400).json({ error: 'Email and password are required' });
    }

    if (!EMAIL_REGEX.test(email)) {
      logSecurityEvent(email, 'USER_REGISTRATION', 'FAILURE', ip, 'Non-institutional email provided');
      return res.status(400).json({ error: 'Only institutional emails (@university.edu) are allowed' });
    }

    if (!PASSWORD_REGEX.test(password)) {
      logSecurityEvent(email, 'USER_REGISTRATION', 'FAILURE', ip, 'Password strength policy violation');
      return res.status(400).json({
        error: 'Password must be at least 12 characters long and contain at least one uppercase letter, one lowercase letter, one digit, and one special character.'
      });
    }

    // Check if user already exists
    const userExists = await User.findOne({ email });
    if (userExists) {
      // Log failure but return generic error to prevent enumeration
      logSecurityEvent(email, 'USER_REGISTRATION', 'FAILURE', ip, 'Email already registered');
      return res.status(400).json({ error: 'Invalid registration credentials' });
    }

    const user = new User({
      email,
      password,
      role: 'Reporter'
    });

    await user.save();
    logSecurityEvent(user._id, 'USER_REGISTRATION', 'SUCCESS', ip, `User created: ${email}`);
    res.status(201).json({ message: 'User registered successfully. You can now login.' });
  } catch (error) {
    logSecurityEvent('unauthenticated', 'USER_REGISTRATION', 'ERROR', ip, error.message);
    res.status(500).json({ error: 'Server error during registration' });
  }
});

/**
 * @route   POST /api/auth/login
 * @desc    Authenticate user and create session
 */
router.post('/login', authLimiter, async (req, res) => {
  const ip = req.ip;
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      logSecurityEvent('unauthenticated', 'USER_LOGIN_ATTEMPT', 'FAILURE', ip, 'Missing login arguments');
      return res.status(400).json({ error: 'Email and password are required' });
    }

    const user = await User.findOne({ email });
    if (!user) {
      logSecurityEvent(email, 'USER_LOGIN_ATTEMPT', 'FAILURE', ip, 'Invalid email address');
      return res.status(400).json({ error: 'Invalid email or password' });
    }

    // Check account lockout
    if (user.isLocked()) {
      const remainingTime = Math.ceil((user.lockUntil - Date.now()) / 60000);
      logSecurityEvent(user._id, 'USER_LOGIN_ATTEMPT', 'FAILURE', ip, 'Account locked out');
      return res.status(423).json({
        error: `Account is locked due to multiple failed login attempts. Try again in ${remainingTime} minute(s).`
      });
    }

    const isMatch = await user.comparePassword(password);
    if (!isMatch) {
      user.loginAttempts += 1;
      if (user.loginAttempts >= 5) {
        user.lockUntil = Date.now() + 15 * 60 * 1000; // 15 min lockout
        await user.save();
        logSecurityEvent(user._id, 'USER_LOCKOUT', 'LOCKED', ip, '5 failed attempts reached');
        return res.status(423).json({
          error: 'Account locked due to 5 consecutive failed login attempts. Try again in 15 minutes.'
        });
      }
      await user.save();
      logSecurityEvent(user._id, 'USER_LOGIN_ATTEMPT', 'FAILURE', ip, 'Password mismatch');
      return res.status(400).json({ error: 'Invalid email or password' });
    }

    // Reset login attempts on successful login
    user.loginAttempts = 0;
    user.lockUntil = null;
    await user.save();

    // Store user data in session
    req.session.userId = user._id;
    req.session.role = user.role;

    if (user.mfaEnabled) {
      req.session.mfaVerified = false;
      logSecurityEvent(user._id, 'USER_LOGIN_MFA_STAGE', 'PENDING', ip, 'MFA challenge prompted');
      return res.json({
        message: 'MFA verification required',
        mfaRequired: true
      });
    }

    req.session.mfaVerified = true;
    logSecurityEvent(user._id, 'USER_LOGIN', 'SUCCESS', ip, 'Session authorized');
    res.json({
      message: 'Login successful',
      user: {
        id: user._id,
        email: user.email,
        role: user.role,
        mfaEnabled: user.mfaEnabled
      }
    });
  } catch (error) {
    logSecurityEvent('unauthenticated', 'USER_LOGIN', 'ERROR', ip, error.message);
    res.status(500).json({ error: 'Server error during login' });
  }
});

/**
 * @route   POST /api/auth/logout
 * @desc    Destroy session and log user out
 */
router.post('/logout', (req, res) => {
  const userId = req.session.userId || 'anonymous';
  const ip = req.ip;
  req.session.destroy((err) => {
    if (err) {
      logSecurityEvent(userId, 'USER_LOGOUT', 'FAILURE', ip, err.message);
      return res.status(500).json({ error: 'Could not log out' });
    }
    res.clearCookie('sid');
    logSecurityEvent(userId, 'USER_LOGOUT', 'SUCCESS', ip, 'Session destroyed');
    res.json({ message: 'Logout successful' });
  });
});

/**
 * @route   GET /api/auth/me
 * @desc    Get current user details (if authenticated)
 */
router.get('/me', async (req, res) => {
  if (!req.session.userId) {
    return res.status(401).json({ error: 'Not authenticated' });
  }

  if (req.session.mfaVerified === false) {
    return res.status(401).json({ error: 'MFA verification required', mfaRequired: true });
  }

  try {
    const user = await User.findById(req.session.userId).select('-password -mfaSecret');
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }
    res.json({ user });
  } catch (error) {
    res.status(500).json({ error: 'Server error retrieving profile' });
  }
});

module.exports = router;
