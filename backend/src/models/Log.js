const mongoose = require('mongoose');

const logSchema = new mongoose.Schema({
  level: {
    type: String,
    enum: ['info', 'warning', 'error', 'critical'],
    default: 'info'
  },
  action: {
    type: String,
    required: true,
    index: true
  },
  userId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    index: true
  },
  protocol: {
    id: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'Protocol'
    },
    type: String,
    name: String
  },
  details: {
    type: String,
    required: true
  },
  metadata: {
    ip: String,
    userAgent: String,
    path: String,
    method: String,
    statusCode: Number,
    responseTime: Number
  },
  error: {
    message: String,
    stack: String,
    code: String
  }
}, {
  timestamps: true
});

logSchema.index({ createdAt: 1 });
logSchema.index({ level: 1, createdAt: 1 });
logSchema.index({ 'protocol.id': 1, createdAt: 1 });

logSchema.statics.createSystemLog = function(action, details, level = 'info') {
  return this.create({
    action,
    details,
    level
  });
};

logSchema.statics.createUserLog = function(userId, action, details, level = 'info') {
  return this.create({
    userId,
    action,
    details,
    level
  });
};

logSchema.statics.createErrorLog = function(error, metadata = {}) {
  return this.create({
    level: 'error',
    action: 'SYSTEM_ERROR',
    details: error.message,
    error: {
      message: error.message,
      stack: error.stack,
      code: error.code
    },
    metadata
  });
};

const Log = mongoose.model('Log', logSchema);

module.exports = Log;
