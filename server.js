require('dotenv').config();
const express = require('express');
const session = require('express-session');
const MongoStore = require('connect-mongo');
const helmet = require('helmet');
const connectDB = require('./config/db');
const sanitizeMiddleware = require('./middleware/sanitize');

// Initialize database connection
connectDB();

const app = express();

// Enable Helmet middleware to secure HTTP headers
app.use(helmet());

// Body parsers
app.use(express.json({ limit: '10kb' })); // Restrict payload size to prevent DoS attacks
app.use(express.urlencoded({ extended: true, limit: '10kb' }));

// Custom NoSQL query sanitization middleware
app.use(sanitizeMiddleware);

// Session configuration
app.use(session({
  name: 'sid', // Generic name to avoid framework fingerprinting (CWE-521)
  secret: process.env.SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  store: MongoStore.create({
    mongoUrl: process.env.MONGO_URI,
    collectionName: 'sessions',
    ttl: 24 * 60 * 60 // Session expires in 1 day
  }),
  cookie: {
    httpOnly: true, // Prevents client-side scripts from reading the session cookie (XSS protection)
    secure: process.env.NODE_ENV === 'production', // Use secure cookies in production (HTTPS)
    sameSite: 'strict', // Protects against Cross-Site Request Forgery (CSRF)
    maxAge: 24 * 60 * 60 * 1000 // 1 day
  }
}));

// Route mappings
app.use('/api/auth', require('./routes/auth'));

// 404 handler for unmatched routes
app.use((req, res) => {
  res.status(404).json({ error: 'Endpoint not found' });
});

// Secure error-handling middleware to prevent stack trace leaks (CWE-209)
app.use((err, req, res, next) => {
  console.error(err.stack);
  res.status(500).json({
    error: process.env.NODE_ENV === 'production' ? 'An unexpected server error occurred' : err.message
  });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`CampusWhisper Server running in ${process.env.NODE_ENV} mode on port ${PORT}`);
});
