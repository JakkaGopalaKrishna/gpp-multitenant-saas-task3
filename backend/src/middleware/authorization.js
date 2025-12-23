const authorizeRoles = (...allowedRoles) => {
  return (req, res, next) => {
    if (!req.user) {
      return res.status(401).json({ success: false, message: 'Authentication required' });
    }

    if (allowedRoles.includes(req.user.role)) {
      return next();
    }

    return res.status(403).json({ success: false, message: 'Insufficient permissions' });
  };
};

const authorizeTenantAccess = (req, res, next) => {
  if (!req.user) {
    return res.status(401).json({ success: false, message: 'Authentication required' });
  }

  const tenantIdFromParam = req.params.tenantId;
  const userTenantId = req.user.tenantId;
  const userRole = req.user.role;

  if (userRole === 'super_admin') {
    return next();
  }

  if (userTenantId === tenantIdFromParam) {
    return next();
  }

  return res.status(403).json({ success: false, message: 'Unauthorized access to this tenant' });
};

module.exports = { authorizeRoles, authorizeTenantAccess };
