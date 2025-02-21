const express = require('express');
const router = express.Router();
const authController = require('../controllers/authController');
const { authLimiter } = require('../middleware/rateLimit');
const auth = require('../middleware/auth');

// Public routes
router.post('/login', authLimiter, authController.login);
router.post('/register', authLimiter, authController.register);
router.post('/forgot-password', authLimiter, authController.forgotPassword);
router.post('/reset-password', authLimiter, authController.resetPassword);

// Protected routes
router.use(auth);
router.post('/logout', authController.logout);
router.get('/profile', authController.getProfile);
router.put('/profile', authController.updateProfile);
router.post('/change-password', authController.changePassword);
router.get('/sessions', authController.getSessions);
router.delete('/sessions/:id', authController.terminateSession);

module.exports = router;
