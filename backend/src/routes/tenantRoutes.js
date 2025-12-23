const express = require('express');
const { getTenantDetails, updateTenant, listAllTenants } = require('../controllers/tenantController');
const { authenticateToken } = require('../middleware/auth');
const { authorizeRoles, authorizeTenantAccess } = require('../middleware/authorization');

const router = express.Router();

router.get('/', authenticateToken, authorizeRoles('super_admin'), listAllTenants);
router.get('/:tenantId', authenticateToken, authorizeTenantAccess, getTenantDetails);
router.put('/:tenantId', authenticateToken, authorizeTenantAccess, updateTenant);

module.exports = router;
