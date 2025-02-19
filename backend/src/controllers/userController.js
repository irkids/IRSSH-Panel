const User = require('../models/User');
const Log = require('../models/Log');

class UserController {
  async createUser(req, res) {
    try {
      const userData = req.body;
      const user = await User.create(userData);
      await Log.create({
        action: 'CREATE_USER',
        userId: req.user._id,
        details: `Created user: ${user.username}`
      });
      res.status(201).json(user);
    } catch (error) {
      res.status(400).json({ error: error.message });
    }
  }

  async updateUser(req, res) {
    try {
      const { id } = req.params;
      const updates = req.body;
      const user = await User.findByIdAndUpdate(id, updates, { new: true });
      
      if (!user) {
        return res.status(404).json({ error: 'User not found' });
      }

      await Log.create({
        action: 'UPDATE_USER',
        userId: req.user._id,
        details: `Updated user: ${user.username}`
      });

      res.json(user);
    } catch (error) {
      res.status(400).json({ error: error.message });
    }
  }

  async deleteUser(req, res) {
    try {
      const { id } = req.params;
      const user = await User.findByIdAndDelete(id);
      
      if (!user) {
        return res.status(404).json({ error: 'User not found' });
      }

      await Log.create({
        action: 'DELETE_USER',
        userId: req.user._id,
        details: `Deleted user: ${user.username}`
      });

      res.json({ message: 'User deleted successfully' });
    } catch (error) {
      res.status(400).json({ error: error.message });
    }
  }

  async listUsers(req, res) {
    try {
      const users = await User.find({}).select('-password');
      res.json(users);
    } catch (error) {
      res.status(500).json({ error: error.message });
    }
  }
}

module.exports = new UserController();
