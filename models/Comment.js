const mongoose = require('mongoose');
const { encrypt, decrypt } = require('../utils/crypto');

const CommentSchema = new mongoose.Schema({
  report: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'Report',
    required: true
  },
  author: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true
  },
  authorRole: {
    type: String,
    enum: ['Reporter', 'Moderator', 'Admin'],
    required: true
  },
  text: {
    type: String, // Stored encrypted
    required: [true, 'Comment content is required']
  }
}, {
  timestamps: true
});

// Auto-encrypt comment text before saving
CommentSchema.pre('save', function (next) {
  if (this.isModified('text') && !this.text.includes(':')) {
    this.text = encrypt(this.text);
  }
  next();
});

// Decrypt comment text for reading
CommentSchema.methods.getDecryptedText = function () {
  try {
    return decrypt(this.text);
  } catch (err) {
    return '[Decryption Failed]';
  }
};

module.exports = mongoose.model('Comment', CommentSchema);
