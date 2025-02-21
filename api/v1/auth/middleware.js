const jwt = require('jsonwebtoken');
const Session = require('../models/Session');
const { createError } = require('../utils/error');

const authMiddleware = async (req, res, next) => {
  try {
    const token = req.headers.authorization?.split(' ')[1];
    
    if (!token) {
      throw createError(401, 'No token provided');
    }

    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    
    // Check if session exists and is active
    const session = await Session.findOne({ 
      token,
      userId: decoded.id,
      isActive: true 
    });

    if (!session) {
      throw createError(401, 'Invalid or expired session');
    }

    // Update last activity
    await session.updateActivity();

    req.user = decoded;
    req.session = session;
    next();
  } catch (error) {
    next(createError(401, 'Authentication failed'));
  }
};

module.exports = authMiddleware;
