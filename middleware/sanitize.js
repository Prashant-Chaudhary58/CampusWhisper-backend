/**
 * Middleware to sanitize user input and prevent NoSQL Operator Injection.
 * Recursively removes keys starting with '$' or containing dots ('.') from input objects.
 */
const sanitizeInput = (obj) => {
  if (obj && typeof obj === 'object') {
    for (const key in obj) {
      if (key.startsWith('$') || key.includes('.')) {
        delete obj[key];
      } else {
        sanitizeInput(obj[key]);
      }
    }
  }
};

const sanitizeMiddleware = (req, res, next) => {
  sanitizeInput(req.body);
  sanitizeInput(req.query);
  sanitizeInput(req.params);
  next();
};

module.exports = sanitizeMiddleware;
