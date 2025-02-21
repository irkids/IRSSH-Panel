const Log = require('../../models/Log');
const emailService = require('../../services/email');

class ErrorReporter {
  async report(error, req = null) {
    try {
      // Log the error
      const logEntry = await Log.create({
        level: 'error',
        action: 'SYSTEM_ERROR',
        details: error.message,
        error: {
          name: error.name,
          message: error.message,
          stack: error.stack,
          code: error.code
        },
        metadata: req ? {
          ip: req.ip,
          method: req.method,
          path: req.path,
          userAgent: req.get('user-agent')
        } : null
      });

      // Send notification for critical errors
      if (this.isCriticalError(error)) {
        await this.notifyAdmins(error, logEntry);
      }

      return logEntry;
    } catch (reportingError) {
      console.error('Error reporting error:', reportingError);
    }
  }

  isCriticalError(error) {
    const criticalErrors = [
      'DatabaseConnectionError',
      'SystemCrashError',
      'SecurityBreachError'
    ];

    return criticalErrors.includes(error.name) || error.critical === true;
  }

  async notifyAdmins(error, logEntry) {
    const notification = {
      subject: `Critical Error: ${error.name}`,
      template: 'error-notification',
      data: {
        error: {
          name: error.name,
          message: error.message,
          code: error.code
        },
        logEntry: {
          id: logEntry._id,
          timestamp: logEntry.createdAt,
          metadata: logEntry.metadata
        },
        environment: process.env.NODE_ENV
      }
    };

    await emailService.sendToAdmins(notification);
  }
}

module.exports = new ErrorReporter();
