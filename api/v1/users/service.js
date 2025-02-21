const User = require('../models/User');
const Log = require('../models/Log');
const { createError } = require('../utils/error');
const emailService = require('../services/email');

class UserService {
  async listUsers(filters = {}, options = {}) {
    const users = await User.find(filters, null, options)
      .select('-password')
      .sort({ createdAt: -1 });
    
    return users;
  }

  async createUser(userData) {
    const existingUser = await User.findOne({
      $or: [
        { username: userData.username },
        { email: userData.email }
      ]
    });

    if (existingUser) {
      throw createError(409, 'Username or email already exists');
    }

    const user = await User.create(userData);
    await emailService.sendWelcomeEmail(user.email);
    
    return user;
  }

  async updateUser(id, updates) {
    const user = await User.findByIdAndUpdate(id, updates, {
      new: true,
      runValidators: true
    });

    if (!user) {
      throw createError(404, 'User not found');
    }

    return user;
  }

  async deleteUser(id) {
    const user = await User.findById(id);
    
    if (!user) {
      throw createError(404, 'User not found');
    }

    await Log.create({
      action: 'USER_DELETED',
      details: `User ${user.username} was deleted`
    });

    await user.remove();
  }

  async getUserActivity(id) {
    const logs = await Log.find({ userId: id })
      .sort({ createdAt: -1 })
      .limit(100);
    
    return logs;
  }
}

module.exports = new UserService();
