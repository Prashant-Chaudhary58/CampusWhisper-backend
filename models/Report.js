const mongoose = require('mongoose');
const { encrypt, decrypt } = require('../utils/crypto');

const ReportSchema = new mongoose.Schema({
  caseId: {
    type: String,
    required: true,
    unique: true
  },
  title: {
    type: String, // Stored encrypted
    required: [true, 'Title is required']
  },
  description: {
    type: String, // Stored encrypted
    required: [true, 'Description is required']
  },
  category: {
    type: String,
    required: [true, 'Category is required'],
    enum: ['Harassment', 'Safety Issue', 'Academic Misconduct', 'Other']
  },
  status: {
    type: String,
    enum: ['Open', 'Under Review', 'Resolved'],
    default: 'Open'
  },
  isAnonymous: {
    type: Boolean,
    default: false
  },
  isPinned: {
    type: Boolean,
    default: false
  },
  // Plain link to User (null if report is anonymous)
  reporter: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    default: null
  },
  // Encrypted link to User (null if report is public)
  encryptedReporterId: {
    type: String,
    default: null
  },
  // One-way cryptographic hash of User ID (allows users to query their own reports securely)
  reporterPseudonym: {
    type: String,
    default: null,
    index: true
  },
  attachments: [{
    filename: String,
    originalName: String,
    mimeType: String,
    size: Number
  }]
}, {
  timestamps: true
});

// Middleware hooks to automatically encrypt fields before saving
ReportSchema.pre('save', function (next) {
  // Encrypt title and description if they are modified and not already encrypted
  if (this.isModified('title') && !this.title.includes(':')) {
    this.title = encrypt(this.title);
  }
  if (this.isModified('description') && !this.description.includes(':')) {
    this.description = encrypt(this.description);
  }
  next();
});

// Helper method to get decrypted fields for authorized read access
ReportSchema.methods.getDecryptedData = function () {
  const reportObj = this.toObject();
  try {
    reportObj.title = decrypt(this.title);
  } catch (err) {
    reportObj.title = '[Decryption Failed]';
  }
  try {
    reportObj.description = decrypt(this.description);
  } catch (err) {
    reportObj.description = '[Decryption Failed]';
  }
  return reportObj;
};

module.exports = mongoose.model('Report', ReportSchema);
