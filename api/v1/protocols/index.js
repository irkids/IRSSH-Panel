const express = require('express');
const router = express.Router();
const protocolController = require('../controllers/protocolController');
const auth = require('../middleware/auth');

router.use(auth);

router.get('/', protocolController.listProtocols);
router.post('/', protocolController.createProtocol);
router.get('/:id', protocolController.getProtocol);
router.put('/:id', protocolController.updateProtocol);
router.delete('/:id', protocolController.deleteProtocol);
router.get('/:id/metrics', protocolController.getProtocolMetrics);
router.post('/:id/test', protocolController.testProtocol);
router.put('/:id/enable', protocolController.enableProtocol);
router.put('/:id/disable', protocolController.disableProtocol);

module.exports = router;
