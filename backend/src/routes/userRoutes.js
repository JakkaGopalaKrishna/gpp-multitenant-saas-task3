const express = require('express');
const { addUserToTenant, listTenantUsers, updateUser, deleteUser } = require('../controllers/userController');
const { authenticateToken } = require('../middleware/auth');
const { authorizeRoles } = require('../middleware/authorization');

const router = express.Router();

// Tenant users
router.post('/:tenantId/users', authenticateToken, addUserToTenant);
router.get('/:tenantId/users', authenticateToken, listTenantUsers);

// Individual user
router.put('/users/:userId', authenticateToken, updateUser);
router.delete('/users/:userId', authenticateToken, deleteUser);

module.exports = router;
