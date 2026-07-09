const crypto = require('crypto');

/**
 * Middleware to enforce CSRF token checks on state-changing requests (POST, PUT, PATCH, DELETE).
 */
const csrfProtection = (req, res, next) => {
  // Allow safe HTTP methods (GET, HEAD, OPTIONS) without checks
  const safeMethods = ['GET', 'HEAD', 'OPTIONS'];
  if (safeMethods.includes(req.method)) {
    // Generate a CSRF token if it doesn't exist in the session yet
    if (!req.session.csrfToken) {
      req.session.csrfToken = crypto.randomBytes(32).toString('hex');
    }
    return next();
  }

  // Retrieve token from request headers
  const clientToken = req.headers['x-csrf-token'];
  const sessionToken = req.session.csrfToken;

  if (!clientToken || !sessionToken || clientToken !== sessionToken) {
    return res.status(403).json({ error: 'CSRF token validation failed. Request untrusted.' });
  }

  next();
};

/**
 * Route controller to retrieve a fresh CSRF token.
 */
const getCsrfToken = (req, res) => {
  if (!req.session.csrfToken) {
    req.session.csrfToken = crypto.randomBytes(32).toString('hex');
  }
  res.json({ csrfToken: req.session.csrfToken });
};

module.exports = {
  csrfProtection,
  getCsrfToken
};
