const Protocol = require('../models/Protocol');
const Log = require('../models/Log');
const { createError } = require('../utils/error');
const metricsService = require('../services/metrics');

class ProtocolService {
  async listProtocols() {
    const protocols = await Protocol.find()
      .sort({ name: 1 });
    
    return protocols;
  }

  async createProtocol(data) {
    const existingProtocol = await Protocol.findOne({ name: data.name });
    
    if (existingProtocol) {
      throw createError(409, 'Protocol with this name already exists');
    }

    const protocol = await Protocol.create(data);
    
    await Log.create({
      action: 'PROTOCOL_CREATED',
      details: `Protocol ${protocol.name} was created`
    });

    return protocol;
  }

  async updateProtocol(id, updates) {
    const protocol = await Protocol.findByIdAndUpdate(id, updates, {
      new: true,
      runValidators: true
    });

    if (!protocol) {
      throw createError(404, 'Protocol not found');
    }

    await Log.create({
      action: 'PROTOCOL_UPDATED',
      details: `Protocol ${protocol.name} was updated`
    });

    return protocol;
  }

  async deleteProtocol(id) {
    const protocol = await Protocol.findById(id);
    
    if (!protocol) {
      throw createError(404, 'Protocol not found');
    }

    if (protocol.currentConnections > 0) {
      throw createError(400, 'Cannot delete protocol with active connections');
    }

    await Log.create({
      action: 'PROTOCOL_DELETED',
      details: `Protocol ${protocol.name} was deleted`
    });

    await protocol.remove();
  }

  async getProtocolMetrics(id) {
    const protocol = await Protocol.findById(id);
    
    if (!protocol) {
      throw createError(404, 'Protocol not found');
    }

    const metrics = await metricsService.getProtocolMetrics(protocol);
    return metrics;
  }
}

module.exports = new ProtocolService();
