const Log = require('../models/Log');
const Protocol = require('../models/Protocol');
const User = require('../models/User');

class MetricsController {
  async getSystemMetrics(req, res) {
    try {
      const userCount = await User.countDocuments();
      const protocolCount = await Protocol.countDocuments();
      const recentLogs = await Log.find()
        .sort({ createdAt: -1 })
        .limit(100);

      const metrics = {
        users: {
          total: userCount,
          active: await User.countDocuments({ status: 'active' })
        },
        protocols: {
          total: protocolCount,
          byType: await Protocol.aggregate([
            { $group: { _id: '$type', count: { $sum: 1 } } }
          ])
        },
        logs: {
          recent: recentLogs,
          errorCount: await Log.countDocuments({ level: 'error' })
        }
      };

      res.json(metrics);
    } catch (error) {
      res.status(500).json({ error: error.message });
    }
  }

  async getProtocolMetrics(req, res) {
    try {
      const { id } = req.params;
      const protocol = await Protocol.findById(id);
      
      if (!protocol) {
        return res.status(404).json({ error: 'Protocol not found' });
      }

      const metrics = {
        usage: await Log.aggregate([
          { $match: { 'protocol.id': protocol._id } },
          { $group: { _id: { $dateToString: { format: '%Y-%m-%d', date: '$createdAt' } },
            count: { $sum: 1 } } },
          { $sort: { _id: -1 } },
          { $limit: 30 }
        ]),
        errors: await Log.find({
          'protocol.id': protocol._id,
          level: 'error'
        }).sort({ createdAt: -1 }).limit(50)
      };

      res.json(metrics);
    } catch (error) {
      res.status(500).json({ error: error.message });
    }
  }

  async getUserMetrics(req, res) {
    try {
      const { id } = req.params;
      const user = await User.findById(id);
      
      if (!user) {
        return res.status(404).json({ error: 'User not found' });
      }

      const metrics = {
        activity: await Log.aggregate([
          { $match: { userId: user._id } },
          { $group: { _id: '$action', count: { $sum: 1 } } }
        ]),
        lastLogin: await Log.findOne({ 
          userId: user._id,
          action: 'LOGIN'
        }).sort({ createdAt: -1 }),
        protocolUsage: await Log.aggregate([
          { $match: { userId: user._id, 'protocol': { $exists: true } } },
          { $group: { _id: '$protocol.type', count: { $sum: 1 } } }
        ])
      };

      res.json(metrics);
    } catch (error) {
      res.status(500).json({ error: error.message });
    }
  }
}

module.exports = new MetricsController();
