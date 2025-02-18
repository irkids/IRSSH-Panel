// /opt/irssh-panel/backend/src/routes/vpn.js
const express = require('express');
const router = express.Router();
const auth = require('../middleware/auth');
const { VPNAccount, Session } = require('../models');
const { spawn } = require('child_process');

router.post('/account', auth, async (req, res) => {
    try {
        const { protocol, username } = req.body;
        const account = await VPNAccount.create({
            userId: req.user.id,
            protocol,
            username,
            status: 'active'
        });
        
        // Execute protocol-specific script
        const script = spawn(`/opt/irssh-panel/modules/protocols/${protocol}-script.py`, ['create', username]);
        
        script.on('close', (code) => {
            if (code !== 0) {
                account.destroy();
                return res.status(500).json({ message: 'Failed to create VPN account' });
            }
            res.json(account);
        });
    } catch (error) {
        res.status(500).json({ message: error.message });
    }
});

module.exports = router;
