const express = require('express');
const router = express.Router();
const userController = require('../controllers/userController');
const auth = require('../middleware/auth');
const { userLimiter } = require('../middleware/rateLimit');

router.use(auth);
router.use(userLimiter);

router.get('/', userController.listUsers);
router.post('/', userController.createUser);
router.get('/:id', userController.getUser);
router.put('/:id', userController.updateUser);
router.delete('/:id', userController.deleteUser);
router.get('/:id/activity', userController.getUserActivity);
router.get('/:id/permissions', userController.getUserPermissions);
router.put('/:id/status', userController.updateUserStatus);

module.exports = router;
