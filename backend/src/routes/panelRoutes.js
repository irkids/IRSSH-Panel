const express = require('express');
const router = express.Router();
const auth = require('../middleware/auth');
const { 
  MetricsController,
  ProtocolController,
  UserController
} = require('../controllers');

// Metrics routes
router.get('/metrics/system', auth, MetricsController.getSystemMetrics);
router.get('/metrics/protocol/:id', auth, MetricsController.getProtocolMetrics);
router.get('/metrics/user/:id', auth, MetricsController.getUserMetrics);

// Protocol routes
router.get('/protocols', auth, ProtocolController.listProtocols);
router.post('/protocols', auth, ProtocolController.createProtocol);
router.put('/protocols/:id', auth, ProtocolController.updateProtocol);
router.delete('/protocols/:id', auth, ProtocolController.deleteProtocol);

// User management routes
router.get('/users', auth, UserController.listUsers);
router.post('/users', auth, UserController.createUser);
router.put('/users/:id', auth, UserController.updateUser);
router.delete('/users/:id', auth, UserController.deleteUser);

module.exports = router;
