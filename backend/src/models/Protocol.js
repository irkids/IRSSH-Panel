const mongoose = require('mongoose');

const protocolSchema = new mongoose.Schema({
  name: {
    type: String,
    required: true,
    unique: true
  },
  type: {
    type: String,
    enum: ['SSH', 'L2TP', 'IKEv2', 'CISCO', 'WIREGUARD', 'SINGBOX'],
    required: true
  },
  config: {
    type: mongoose.Schema.Types.Mixed,
    required: true
  },
  enabled: {
    type: Boolean,
    default: true
  },
  maxConnections: {
    type: Number,
    default: 100
  },
  currentConnections: {
    type: Number,
    default: 0
  },
  settings: {
    encryption: {
      type: String,
      required: true
    },
    ports: [{
      type: Number,
      required: true
    }],
    timeout: {
      type: Number,
      default: 3600
    }
  },
  metadata: {
    description: String,
    tags: [String],
    version: String
  }
}, {
  timestamps: true
});

protocolSchema.index({ type: 1, enabled: 1 });
protocolSchema.index({ name: 1 }, { unique: true });

const Protocol = mongoose.model('Protocol', protocolSchema);

module.exports = Protocol;
