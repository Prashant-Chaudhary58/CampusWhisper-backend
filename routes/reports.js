const express = require('express');
const router = express.Router();
const crypto = require('crypto');
const Report = require('../models/Report');
const { requireAuth } = require('../middleware/auth');
const upload = require('../middleware/upload');
const { encrypt } = require('../utils/crypto');

// Generate a deterministic pseudonym for anonymous queries
const getPseudonym = (userId) => {
  return crypto
    .createHmac('sha256', process.env.ENCRYPTION_KEY)
    .update(userId.toString())
    .digest('hex');
};

/**
 * @route   POST /api/reports
 * @desc    Submit a new incident report (optionally anonymous)
 */
router.post('/', requireAuth, upload.array('attachments', 3), async (req, res) => {
  try {
    const { title, description, category, isAnonymous } = req.body;
    const anonFlag = isAnonymous === 'true' || isAnonymous === true;

    if (!title || !description || !category) {
      return res.status(400).json({ error: 'Title, description, and category are required' });
    }

    const userId = req.session.userId;
    // Generate a unique 8-digit case ID
    const caseId = `CW-${Math.floor(10000000 + Math.random() * 90000000)}`;

    // Structure file details
    const attachments = req.files ? req.files.map(file => ({
      filename: file.filename,
      originalName: file.originalname,
      mimeType: file.mimetype,
      size: file.size
    })) : [];

    const newReport = new Report({
      caseId,
      title,
      description,
      category,
      isAnonymous: anonFlag,
      attachments
    });

    if (anonFlag) {
      // Anonymize the reporter cryptographically
      newReport.encryptedReporterId = encrypt(userId.toString());
      newReport.reporterPseudonym = getPseudonym(userId);
      newReport.reporter = null;
    } else {
      // Connect to reporter directly
      newReport.reporter = userId;
      newReport.reporterPseudonym = null;
      newReport.encryptedReporterId = null;
    }

    await newReport.save();

    res.status(201).json({
      message: 'Report submitted successfully',
      caseId
    });
  } catch (error) {
    console.error('Error submitting report:', error);
    res.status(500).json({ error: error.message || 'Server error while submitting report' });
  }
}, (error, req, res, next) => {
  // Catch Multer errors (e.g. file size exceeded)
  res.status(400).json({ error: error.message });
});

/**
 * @route   GET /api/reports
 * @desc    Retrieve reports based on user role
 */
router.get('/', requireAuth, async (req, res) => {
  try {
    const userId = req.session.userId;
    const role = req.session.role;

    let reports;

    if (role === 'Reporter') {
      // Reporters can only see their own reports (public or anonymous)
      const pseudonym = getPseudonym(userId);
      reports = await Report.find({
        $or: [
          { reporter: userId },
          { reporterPseudonym: pseudonym }
        ]
      }).sort({ createdAt: -1 });
    } else {
      // Moderators and Admins can see all reports
      reports = await Report.find().populate('reporter', 'email').sort({ createdAt: -1 });
    }

    // Decrypt fields before returning them to client
    const decryptedReports = reports.map(report => {
      const decrypted = report.getDecryptedData();
      
      // If report is anonymous, sanitize and remove sensitive fields from moderators/admins
      if (decrypted.isAnonymous) {
        decrypted.reporter = null;
        decrypted.encryptedReporterId = undefined; // Strip from response
        decrypted.reporterPseudonym = undefined;
      }
      return decrypted;
    });

    res.json({ reports: decryptedReports });
  } catch (error) {
    console.error('Error retrieving reports:', error);
    res.status(500).json({ error: 'Server error retrieving reports' });
  }
});

/**
 * @route   GET /api/reports/:caseId
 * @desc    Get a single report by its Case ID
 */
router.get('/:caseId', requireAuth, async (req, res) => {
  try {
    const { caseId } = req.params;
    const userId = req.session.userId;
    const role = req.session.role;

    const report = await Report.findOne({ caseId }).populate('reporter', 'email');
    if (!report) {
      return res.status(404).json({ error: 'Report not found' });
    }

    // Access control check
    if (role === 'Reporter') {
      const pseudonym = getPseudonym(userId);
      const isOwner = report.reporter?.toString() === userId.toString() || report.reporterPseudonym === pseudonym;
      if (!isOwner) {
        return res.status(403).json({ error: 'Access denied' });
      }
    }

    const decrypted = report.getDecryptedData();
    if (decrypted.isAnonymous) {
      decrypted.reporter = null;
      decrypted.encryptedReporterId = undefined;
      decrypted.reporterPseudonym = undefined;
    }

    res.json({ report: decrypted });
  } catch (error) {
    res.status(500).json({ error: 'Server error retrieving report' });
  }
});

module.exports = router;
