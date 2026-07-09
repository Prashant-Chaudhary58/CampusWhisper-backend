/**
 * Middleware to enforce authentication and session verification.
 */
const requireAuth = (req, res, next) => {
  if (!req.session.userId) {
    return res.status(401).json({ error: 'Authentication required. Please log in.' });
  }

  // Enforce MFA completion if enabled for the user
  if (req.session.mfaVerified === false) {
    return res.status(401).json({ error: 'MFA verification required. Please complete multi-factor authentication.' });
  }

  next();
};

module.exports = {
  requireAuth
};
