const mongoose = require('mongoose');
const argon2 = require('argon2');

const UserSchema = new mongoose.Schema({
  email: {
    type: String,
    required: [true, 'Email is required'],
    unique: true,
    trim: true,
    lowercase: true,
    match: [/^\w+([.-]?\w+)*@(university\.edu|softwarica\.edu|coventry\.ac\.uk)$/, 'Please use a valid institutional email (@university.edu, @softwarica.edu, or @coventry.ac.uk)']
  },
  password: {
    type: String,
    required: [true, 'Password is required'],
    minlength: [12, 'Password must be at least 12 characters long']
  },
  role: {
    type: String,
    enum: ['Reporter', 'Moderator', 'Admin'],
    default: 'Reporter'
  },
  mfaSecret: {
    type: String,
    default: null
  },
  mfaEnabled: {
    type: Boolean,
    default: false
  },
  loginAttempts: {
    type: Number,
    required: true,
    default: 0
  },
  lockUntil: {
    type: Date,
    default: null
  }
}, {
  timestamps: true
});

// Pre-save middleware to hash passwords using Argon2
UserSchema.pre('save', async function (next) {
  if (!this.isModified('password')) {
    return next();
  }

  try {
    // Argon2id is the default/recommended variant for general hashing
    this.password = await argon2.hash(this.password, {
      type: argon2.argon2id,
      memoryCost: 2 ** 16, // 64MB
      timeCost: 3,         // 3 iterations
      parallelism: 4       // 4 threads
    });
    next();
  } catch (err) {
    next(err);
  }
});

// Method to compare candidate password with hashed password
UserSchema.methods.comparePassword = async function (candidatePassword) {
  try {
    return await argon2.verify(this.password, candidatePassword);
  } catch (err) {
    return false;
  }
};

// Check if user account is currently locked out
UserSchema.methods.isLocked = function () {
  return !!(this.lockUntil && this.lockUntil > Date.now());
};

module.exports = mongoose.model('User', UserSchema);
