const User = require('../models/User');
const Session = require('../models/Session');
const { generateToken, verifyToken } = require('../utils/security');

class AuthController {
  async login(req, res) {
    try {
      const { username, password } = req.body;
      const user = await User.findOne({ username });
      
      if (!user || !user.comparePassword(password)) {
        return res.status(401).json({ error: 'Invalid credentials' });
      }

      const token = generateToken(user);
      const session = await Session.create({ userId: user._id, token });
      
      res.json({ token, user: user.toJSON() });
    } catch (error) {
      res.status(500).json({ error: error.message });
    }
  }

  async logout(req, res) {
    try {
      await Session.deleteOne({ token: req.token });
      res.json({ message: 'Logged out successfully' });
    } catch (error) {
      res.status(500).json({ error: error.message });
    }
  }

  async verifySession(req, res) {
    try {
      const session = await Session.findOne({ token: req.token });
      if (!session) {
        return res.status(401).json({ error: 'Invalid session' });
      }
      res.json({ valid: true });
    } catch (error) {
      res.status(500).json({ error: error.message });
    }
  }
}

module.exports = new AuthController();
