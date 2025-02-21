const nodemailer = require('nodemailer');
const config = require('../config/email');
const logger = require('./logger');

class EmailService {
  constructor() {
    this.transporter = nodemailer.createTransport(config.transport);
  }

  async send(options) {
    if (!config.enabled) {
      logger.info('Email sending is disabled');
      return;
    }

    try {
      const mailOptions = {
        from: config.from,
        ...options
      };

      const info = await this.transporter.sendMail(mailOptions);
      logger.info('Email sent successfully', { messageId: info.messageId });
      return info;
    } catch (error) {
      logger.error('Email sending failed:', error);
      throw error;
    }
  }

  async sendPasswordReset(email, token) {
    await this.send({
      to: email,
      subject: 'Password Reset Request',
      template: 'password-reset',
      context: {
        resetUrl: `${process.env.APP_URL}/reset-password?token=${token}`
      }
    });
  }

  async sendWelcome(user) {
    await this.send({
      to: user.email,
      subject: 'Welcome to IRSSH Panel',
      template: 'welcome',
      context: {
        username: user.username
      }
    });
  }

  async sendAlert(to, alert) {
    await this.send({
      to,
      subject: `Alert: ${alert.title}`,
      template: 'alert',
      context: {
        alert
      }
    });
  }

  async verifyConnection() {
    try {
      await this.transporter.verify();
      logger.info('Email service is ready');
      return true;
    } catch (error) {
      logger.error('Email service verification failed:', error);
      return false;
    }
  }
}

module.exports = new EmailService();
