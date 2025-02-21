const express = require('express');
const router = express.Router();
const metricsController = require('../controllers/metricsController');
const auth = require('../middleware/auth');

router.use(auth);

router.get('/system', metricsController.getSystemMetrics);
router.get('/protocols', metricsController.getProtocolMetrics);
router.get('/users', metricsController.getUserMetrics);
router.get('/errors', metricsController.getErrorMetrics);
router.get('/bandwidth', metricsController.getBandwidthMetrics);
router.get('/dashboard', metricsController.getDashboardMetrics);

module.exports = router;
