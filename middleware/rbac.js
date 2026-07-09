/**
 * Middleware to enforce Role-Based Access Control (RBAC).
 * @param {Array<string>} allowedRoles - List of roles permitted to access the route
 */
const checkRole = (allowedRoles) => {
  return (req, res, next) => {
    if (!req.session.userId || !req.session.role) {
      return res.status(401).json({ error: 'Authentication required. Please log in.' });
    }

    if (!allowedRoles.includes(req.session.role)) {
      // Forbidden access attempt logged
      return res.status(403).json({ error: 'Access denied. You do not have the required permissions.' });
    }

    next();
  };
};

module.exports = {
  checkRole
};
