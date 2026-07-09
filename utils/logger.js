const fs = require('fs');
const path = require('path');

const logDirectory = path.join(__dirname, '../logs');
if (!fs.existsSync(logDirectory)) {
  fs.mkdirSync(logDirectory, { recursive: true });
}

const logFile = path.join(logDirectory, 'audit.log');

/**
 * Log a security-relevant action to the audit file.
 * Prevents log injection (CWE-117) by sanitizing newlines and control characters.
 * @param {string} userId - User identifier (or 'anonymous'/'unauthenticated')
 * @param {string} action - Description of the action (e.g., 'USER_LOGIN')
 * @param {string} status - Outcome ('SUCCESS', 'FAILURE', etc.)
 * @param {string} ip - Originating IP address
 * @param {string} details - Additional metadata (e.g. Case ID)
 */
const logSecurityEvent = (userId, action, status, ip, details = '') => {
  const timestamp = new Date().toISOString();
  
  // Sanitize variables to prevent log injection/forging
  const cleanUserId = String(userId).replace(/[\r\n]/g, ' ');
  const cleanAction = String(action).replace(/[\r\n]/g, ' ');
  const cleanStatus = String(status).replace(/[\r\n]/g, ' ');
  const cleanIp = String(ip).replace(/[\r\n]/g, ' ');
  const cleanDetails = String(details).replace(/[\r\n]/g, ' ');

  const logLine = `[${timestamp}] [IP:${cleanIp}] [USER:${cleanUserId}] [ACTION:${cleanAction}] [STATUS:${cleanStatus}] DETAILS: ${cleanDetails}\n`;
  
  // Write to log file asynchronously
  fs.appendFile(logFile, logLine, (err) => {
    if (err) {
      console.error('Failed to write to audit log:', err.message);
    }
  });
};

module.exports = {
  logSecurityEvent
};
