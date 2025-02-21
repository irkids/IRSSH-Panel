const express = require('express');
const router = express.Router();
const auth = require('../middleware/auth');
const { userLimiter } = require('../middleware/rateLimit');

const {
  dashboardController,
  protocolController,
  userController,
  metricsController
} = require('../controllers');

// Dashboard routes
router.get('/dashboard/stats', auth, dashboardController.getSystemStats);
router.get('/dashboard/chart-data', auth, dashboardController.getChartData);
router.get('/dashboard/top-protocols', auth, dashboardController.getTopProtocols);
router.get('/dashboard/recent-activity', auth, dashboardController.getRecentActivity);

// Protocol routes
router.get('/protocols', auth, protocolController.getProtocols);
router.get('/protocols/:id', auth, protocolController.getProtocol);
router.post('/protocols', auth, userLimiter, protocolController.createProtocol);
router.put('/protocols/:id', auth, userLimiter, protocolController.updateProtocol);
router.delete('/protocols/:id', auth, userLimiter, protocolController.deleteProtocol);

// User routes
router.get('/users', auth, userController.getUsers);
router.get('/users/:id', auth, userController.getUser);
router.post('/users', auth, userLimiter, userController.createUser);
router.put('/users/:id', auth, userLimiter, userController.updateUser);
router.delete('/users/:id', auth, userLimiter, userController.deleteUser);

// Metrics routes
router.get('/metrics/system', auth, metricsController.getSystemMetrics);
router.get('/metrics/protocol/:id', auth, metricsController.getProtocolMetrics);
router.get('/metrics/user/:id', auth, metricsController.getUserMetrics);
router.get('/metrics/errors', auth, metricsController.getErrorMetrics);

module.exports = router;
