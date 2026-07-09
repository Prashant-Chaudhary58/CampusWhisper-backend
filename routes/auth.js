const express = require('express');
const router = express.Router();
const User = require('../models/User');
const { authLimiter } = require('../middleware/rateLimiter');

// Password complexity regex (Min 12 chars, 1 upper, 1 lower, 1 digit, 1 special)
const PASSWORD_REGEX = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{12,}$/;
// Institutional email domain validator
const EMAIL_REGEX = /^\w+([.-]?\w+)*@university\.edu$/;

/**
 * @route   POST /api/auth/register
 * @desc    Register a new reporter user
 */
router.post('/register', authLimiter, async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({ error: 'Email and password are required' });
    }

    if (!EMAIL_REGEX.test(email)) {
      return res.status(400).json({ error: 'Only institutional emails (@university.edu) are allowed' });
    }

    if (!PASSWORD_REGEX.test(password)) {
      return res.status(400).json({
        error: 'Password must be at least 12 characters long and contain at least one uppercase letter, one lowercase letter, one digit, and one special character.'
      });
    }

    // Check if user already exists
    const userExists = await User.findOne({ email });
    if (userExists) {
      // Return a generic error to prevent email enumeration (CWE-204)
      return res.status(400).json({ error: 'Invalid registration credentials' });
    }

    // Force default 'Reporter' role to prevent privilege escalation during registration
    const user = new User({
      email,
      password,
      role: 'Reporter'
    });

    await user.save();
    res.status(201).json({ message: 'User registered successfully. You can now login.' });
  } catch (error) {
    res.status(500).json({ error: 'Server error during registration' });
  }
});

/**
 * @route   POST /api/auth/login
 * @desc    Authenticate user and create session
 */
router.post('/login', authLimiter, async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({ error: 'Email and password are required' });
    }

    const user = await User.findOne({ email });
    if (!user) {
      // Use generic error for failed login to prevent username harvesting
      return res.status(400).json({ error: 'Invalid email or password' });
    }

    // Check account lockout
    if (user.isLocked()) {
      const remainingTime = Math.ceil((user.lockUntil - Date.now()) / 60000);
      return res.status(423).json({
        error: `Account is locked due to multiple failed login attempts. Try again in ${remainingTime} minute(s).`
      });
    }

    const isMatch = await user.comparePassword(password);
    if (!isMatch) {
      // Increment login attempts
      user.loginAttempts += 1;
      if (user.loginAttempts >= 5) {
        user.lockUntil = Date.now() + 15 * 60 * 1000; // 15 min lockout
        await user.save();
        return res.status(423).json({
          error: 'Account locked due to 5 consecutive failed login attempts. Try again in 15 minutes.'
        });
      }
      await user.save();
      return res.status(400).json({ error: 'Invalid email or password' });
    }

    // Reset login attempts on successful login
    user.loginAttempts = 0;
    user.lockUntil = null;
    await user.save();

    // Store user data in session
    req.session.userId = user._id;
    req.session.role = user.role;

    // Check if MFA is required
    if (user.mfaEnabled) {
      req.session.mfaVerified = false;
      return res.json({
        message: 'MFA verification required',
        mfaRequired: true
      });
    }

    req.session.mfaVerified = true;
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
    res.status(500).json({ error: 'Server error during login' });
  }
});

/**
 * @route   POST /api/auth/logout
 * @desc    Destroy session and log user out
 */
router.post('/logout', (req, res) => {
  req.session.destroy((err) => {
    if (err) {
      return res.status(500).json({ error: 'Could not log out' });
    }
    res.clearCookie('sid');
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

  // Ensure MFA is completed if enabled
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
