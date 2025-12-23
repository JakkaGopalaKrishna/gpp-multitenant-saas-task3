const express = require('express');
const { registerTenant, login, getCurrentUser, logout } = require('../controllers/authController');
const { authenticateToken } = require('../middleware/auth');

const router = express.Router();

router.post('/register-tenant', registerTenant);
router.post('/login', login);
router.get('/me', authenticateToken, getCurrentUser);
router.post('/logout', authenticateToken, logout);

module.exports = router;
