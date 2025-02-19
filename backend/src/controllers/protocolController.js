const Protocol = require('../models/Protocol');
const Log = require('../models/Log');

class ProtocolController {
  async createProtocol(req, res) {
    try {
      const protocolData = req.body;
      const protocol = await Protocol.create(protocolData);
      await Log.create({
        action: 'CREATE_PROTOCOL',
        userId: req.user._id,
        details: `Created protocol: ${protocol.name}`
      });
      res.status(201).json(protocol);
    } catch (error) {
      res.status(400).json({ error: error.message });
    }
  }

  async updateProtocol(req, res) {
    try {
      const { id } = req.params;
      const updates = req.body;
      const protocol = await Protocol.findByIdAndUpdate(id, updates, { new: true });
      
      if (!protocol) {
        return res.status(404).json({ error: 'Protocol not found' });
      }

      await Log.create({
        action: 'UPDATE_PROTOCOL',
        userId: req.user._id,
        details: `Updated protocol: ${protocol.name}`
      });

      res.json(protocol);
    } catch (error) {
      res.status(400).json({ error: error.message });
    }
  }

  async deleteProtocol(req, res) {
    try {
      const { id } = req.params;
      const protocol = await Protocol.findByIdAndDelete(id);
      
      if (!protocol) {
        return res.status(404).json({ error: 'Protocol not found' });
      }

      await Log.create({
        action: 'DELETE_PROTOCOL',
        userId: req.user._id,
        details: `Deleted protocol: ${protocol.name}`
      });

      res.json({ message: 'Protocol deleted successfully' });
    } catch (error) {
      res.status(400).json({ error: error.message });
    }
  }

  async listProtocols(req, res) {
    try {
      const protocols = await Protocol.find({});
      res.json(protocols);
    } catch (error) {
      res.status(500).json({ error: error.message });
    }
  }
}

module.exports = new ProtocolController();
