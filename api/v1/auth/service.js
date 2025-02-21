const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const User = require('../models/User');
const Session = require('../models/Session');
const { createError } = require('../utils/error');
const emailService = require('../services/email');

class AuthService {
  async validateCredentials(username, password) {
    const user = await User.findOne({ username });
    
    if (!user || !(await bcrypt.compare(password, user.password))) {
      throw createError(401, 'Invalid credentials');
    }

    return user;
  }

  async createSession(user, ip, userAgent) {
    const token = jwt.sign(
      { id: user._id, role: user.role },
      process.env.JWT_SECRET,
      { expiresIn: '24h' }
    );

    const session = await Session.create({
      userId: user._id,
      token,
      ipAddress: ip,
      userAgent
    });

    return { token, session };
  }

  async terminateSession(sessionId, userId) {
    const session = await Session.findOne({
      _id: sessionId,
      userId
    });

    if (!session) {
      throw createError(404, 'Session not found');
    }

    session.isActive = false;
    await session.save();
  }

  async resetPassword(email) {
    const user = await User.findOne({ email });
    
    if (!user) {
      throw createError(404, 'User not found');
    }

    const resetToken = crypto.randomBytes(32).toString('hex');
    user.resetPasswordToken = resetToken;
    user.resetPasswordExpires = Date.now() + 3600000; // 1 hour
    await user.save();

    await emailService.sendPasswordReset(user.email, resetToken);
  }
}

module.exports = new AuthService();
