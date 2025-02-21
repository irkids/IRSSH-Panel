const Log = require('../../models/Log');

class LogAggregator {
  async aggregateByTimeRange(startTime, endTime, groupBy = 'hour') {
    const groupings = {
      minute: {
        $minute: '$createdAt'
      },
      hour: {
        $hour: '$createdAt'
      },
      day: {
        $dayOfMonth: '$createdAt'
      }
    };

    return await Log.aggregate([
      {
        $match: {
          createdAt: {
            $gte: startTime,
            $lte: endTime
          }
        }
      },
      {
        $group: {
          _id: {
            year: { $year: '$createdAt' },
            month: { $month: '$createdAt' },
            [groupBy]: groupings[groupBy]
          },
          count: { $sum: 1 },
          errors: {
            $sum: {
              $cond: [{ $eq: ['$level', 'error'] }, 1, 0]
            }
          }
        }
      },
      {
        $sort: { '_id.year': 1, '_id.month': 1, [`_id.${groupBy}`]: 1 }
      }
    ]);
  }

  async aggregateByProtocol(startTime, endTime) {
    return await Log.aggregate([
      {
        $match: {
          createdAt: {
            $gte: startTime,
            $lte: endTime
          },
          'protocol.id': { $exists: true }
        }
      },
      {
        $group: {
          _id: '$protocol.id',
          protocol: { $first: '$protocol.name' },
          count: { $sum: 1 },
          errors: {
            $sum: {
              $cond: [{ $eq: ['$level', 'error'] }, 1, 0]
            }
          }
        }
      }
    ]);
  }

  async aggregateByError(startTime, endTime) {
    return await Log.aggregate([
      {
        $match: {
          createdAt: {
            $gte: startTime,
            $lte: endTime
          },
          level: 'error'
        }
      },
      {
        $group: {
          _id: '$error.code',
          errorMessage: { $first: '$error.message' },
          count: { $sum: 1 }
        }
      },
      {
        $sort: { count: -1 }
      }
    ]);
  }
}

module.exports = new LogAggregator();
