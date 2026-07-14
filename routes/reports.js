const express = require('express');
const router = express.Router();
const crypto = require('crypto');
const path = require('path');
const fs = require('fs');
const Report = require('../models/Report');
const Comment = require('../models/Comment');
const { requireAuth } = require('../middleware/auth');
const { checkRole } = require('../middleware/rbac');
const upload = require('../middleware/upload');
const { encrypt } = require('../utils/crypto');
const { logSecurityEvent } = require('../utils/logger');
const mongoose = require('mongoose');

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
  const ip = req.ip;
  const userId = req.session.userId;
  try {
    const { title, description, category, isAnonymous } = req.body;
    const anonFlag = isAnonymous === 'true' || isAnonymous === true;

    if (!title || !description || !category) {
      logSecurityEvent(userId, 'REPORT_SUBMISSION', 'FAILURE', ip, 'Missing required fields');
      return res.status(400).json({ error: 'Title, description, and category are required' });
    }

    const caseId = `CW-${Math.floor(10000000 + Math.random() * 90000000)}`;

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
      newReport.encryptedReporterId = encrypt(userId.toString());
      newReport.reporterPseudonym = getPseudonym(userId);
      newReport.reporter = null;
    } else {
      newReport.reporter = userId;
      newReport.reporterPseudonym = null;
      newReport.encryptedReporterId = null;
    }

    await newReport.save();

    logSecurityEvent(userId, 'REPORT_SUBMISSION', 'SUCCESS', ip, `Case ID: ${caseId}, Anonymous: ${anonFlag}`);

    res.status(201).json({
      message: 'Report submitted successfully',
      caseId
    });
  } catch (error) {
    logSecurityEvent(userId, 'REPORT_SUBMISSION', 'ERROR', ip, error.message);
    res.status(500).json({ error: error.message || 'Server error while submitting report' });
  }
}, (error, req, res, next) => {
  const userId = req.session ? req.session.userId : 'unauthenticated';
  logSecurityEvent(userId, 'REPORT_SUBMISSION_UPLOAD', 'FAILURE', req.ip, error.message);
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

    reports = await Report.find().populate('reporter', 'email').sort({ createdAt: -1 });

    const decryptedReports = reports.map(report => {
      const decrypted = report.getDecryptedData();
      if (decrypted.isAnonymous) {
        decrypted.reporter = null;
        decrypted.encryptedReporterId = undefined;
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

/**
 * @route   GET /api/reports/:caseId/attachments/:filename
 * @desc    Download an attachment securely
 */
router.get('/:caseId/attachments/:filename', requireAuth, async (req, res) => {
  try {
    const { caseId, filename } = req.params;
    const userId = req.session.userId;
    const role = req.session.role;

    const report = await Report.findOne({ caseId });
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

    // Verify attachment belongs to this report
    const attachment = report.attachments.find(att => att.filename === filename);
    if (!attachment) {
      return res.status(404).json({ error: 'Attachment not found in this report' });
    }

    const filePath = path.join(__dirname, '../uploads', filename);
    
    // Check if file exists on disk
    if (!fs.existsSync(filePath)) {
      return res.status(404).json({ error: 'File not found on disk' });
    }

    // Send the file securely
    res.sendFile(filePath);
  } catch (error) {
    res.status(500).json({ error: 'Server error downloading attachment' });
  }
});

/**
 * @route   PATCH /api/reports/:caseId/status
 * @desc    Update report status (Triage)
 */
router.patch('/:caseId/status', requireAuth, checkRole(['Moderator', 'Admin']), async (req, res) => {
  const ip = req.ip;
  const userId = req.session.userId;
  try {
    const { caseId } = req.params;
    const { status } = req.body;

    if (!['Open', 'Under Review', 'Resolved'].includes(status)) {
      logSecurityEvent(userId, 'REPORT_TRIAGE', 'FAILURE', ip, `Invalid status value attempt: ${status}`);
      return res.status(400).json({ error: 'Invalid status value' });
    }

    const report = await Report.findOneAndUpdate(
      { caseId },
      { status },
      { new: true }
    );

    if (!report) {
      logSecurityEvent(userId, 'REPORT_TRIAGE', 'FAILURE', ip, `Report not found: ${caseId}`);
      return res.status(404).json({ error: 'Report not found' });
    }

    logSecurityEvent(userId, 'REPORT_TRIAGE', 'SUCCESS', ip, `Case ID: ${caseId}, New Status: ${status}`);

    res.json({ message: 'Report status updated successfully', status: report.status });
  } catch (error) {
    logSecurityEvent(userId, 'REPORT_TRIAGE', 'ERROR', ip, error.message);
    res.status(500).json({ error: 'Server error updating status' });
  }
});

/**
 * @route   POST /api/reports/:caseId/comments
 * @desc    Add a comment to an incident report
 */
router.post('/:caseId/comments', requireAuth, async (req, res) => {
  const ip = req.ip;
  const userId = req.session.userId;
  try {
    const { caseId } = req.params;
    const { text } = req.body;
    const role = req.session.role;

    if (!text || text.trim() === '') {
      logSecurityEvent(userId, 'ADD_COMMENT', 'FAILURE', ip, 'Empty comment content');
      return res.status(400).json({ error: 'Comment text cannot be empty' });
    }

    const report = await Report.findOne({ caseId });
    if (!report) {
      logSecurityEvent(userId, 'ADD_COMMENT', 'FAILURE', ip, `Report not found: ${caseId}`);
      return res.status(404).json({ error: 'Report not found' });
    }

    // Access control check for reporters
    if (role === 'Reporter') {
      const pseudonym = getPseudonym(userId);
      const isOwner = report.reporter?.toString() === userId.toString() || report.reporterPseudonym === pseudonym;
      if (!isOwner) {
        logSecurityEvent(userId, 'ADD_COMMENT_ATTEMPT', 'UNAUTHORIZED', ip, `BOLA/IDOR attempt on Case ID: ${caseId}`);
        return res.status(403).json({ error: 'Access denied' });
      }
    }

    const comment = new Comment({
      report: report._id,
      author: userId,
      authorRole: role,
      text
    });

    await comment.save();
    
    logSecurityEvent(userId, 'ADD_COMMENT', 'SUCCESS', ip, `Case ID: ${caseId}`);
    
    res.status(201).json({ message: 'Comment added successfully' });
  } catch (error) {
    logSecurityEvent(userId, 'ADD_COMMENT', 'ERROR', ip, error.message);
    res.status(500).json({ error: 'Server error adding comment' });
  }
});

/**
 * @route   GET /api/reports/:caseId/comments
 * @desc    Get comment thread for an incident report
 */
router.get('/:caseId/comments', requireAuth, async (req, res) => {
  try {
    const { caseId } = req.params;
    const userId = req.session.userId;
    const role = req.session.role;

    const report = await Report.findOne({ caseId });
    if (!report) {
      return res.status(404).json({ error: 'Report not found' });
    }

    // Access control check for reporters
    if (role === 'Reporter') {
      const pseudonym = getPseudonym(userId);
      const isOwner = report.reporter?.toString() === userId.toString() || report.reporterPseudonym === pseudonym;
      if (!isOwner) {
        logSecurityEvent(userId, 'GET_COMMENTS_ATTEMPT', 'UNAUTHORIZED', req.ip, `BOLA/IDOR query attempt on Case ID: ${caseId}`);
        return res.status(403).json({ error: 'Access denied' });
      }
    }

    const comments = await Comment.find({ report: report._id })
      .populate('author', 'email')
      .sort({ createdAt: 1 });

    const decryptedComments = comments.map(comment => {
      const decryptedText = comment.getDecryptedText();
      const commentObj = comment.toObject();
      commentObj.text = decryptedText;

      if (report.isAnonymous && commentObj.authorRole === 'Reporter') {
        commentObj.author = null;
      }
      
      return commentObj;
    });

    res.json({ comments: decryptedComments });
  } catch (error) {
    console.error('Error fetching comments:', error);
    res.status(500).json({ error: 'Server error retrieving comments' });
  }
});

module.exports = router;
