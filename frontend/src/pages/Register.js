import React, { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import api from '../services/api';

const Register = () => {
  const navigate = useNavigate();
  const [formData, setFormData] = useState({
    tenantName: '',
    subdomain: '',
    adminEmail: '',
    adminPassword: '',
    adminFullName: '',
    confirmPassword: ''
  });
  const [errors, setErrors] = useState({});
  const [loading, setLoading] = useState(false);
  const [message, setMessage] = useState('');

  const handleChange = (e) => {
    const { name, value } = e.target;
    setFormData(prev => ({ ...prev, [name]: value }));
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    const newErrors = {};

    if (!formData.tenantName) newErrors.tenantName = 'Organization name required';
    if (!formData.subdomain) newErrors.subdomain = 'Subdomain required';
    if (!/^[a-z0-9]([a-z0-9-]*[a-z0-9])?$/.test(formData.subdomain)) newErrors.subdomain = 'Invalid subdomain format';
    if (!formData.adminEmail) newErrors.adminEmail = 'Email required';
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(formData.adminEmail)) newErrors.adminEmail = 'Invalid email';
    if (!formData.adminPassword || formData.adminPassword.length < 8) newErrors.adminPassword = 'Password must be 8+ characters';
    if (formData.adminPassword !== formData.confirmPassword) newErrors.confirmPassword = 'Passwords do not match';
    if (!formData.adminFullName) newErrors.adminFullName = 'Full name required';

    if (Object.keys(newErrors).length > 0) {
      setErrors(newErrors);
      return;
    }

    setLoading(true);
    try {
      await api.post('/auth/register-tenant', {
        tenantName: formData.tenantName,
        subdomain: formData.subdomain,
        adminEmail: formData.adminEmail,
        adminPassword: formData.adminPassword,
        adminFullName: formData.adminFullName
      });
      setMessage('Registration successful! Redirecting to login...');
      setTimeout(() => navigate('/login'), 2000);
    } catch (error) {
      const errorMsg = error.response?.data?.message || 'Registration failed';
      setMessage(errorMsg);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="container mt-5">
      <div className="row justify-content-center">
        <div className="col-md-6">
          <div className="card shadow">
            <div className="card-body p-4">
              <h2 className="card-title text-center mb-4">Register Your Organization</h2>
              {message && <div className={`alert ${message.includes('successful') ? 'alert-success' : 'alert-danger'}`}>{message}</div>}
              <form onSubmit={handleSubmit}>
                <div className="mb-3">
                  <label className="form-label">Organization Name</label>
                  <input type="text" className={`form-control ${errors.tenantName ? 'is-invalid' : ''}`} name="tenantName" value={formData.tenantName} onChange={handleChange} />
                  {errors.tenantName && <div className="invalid-feedback d-block">{errors.tenantName}</div>}
                </div>
                <div className="mb-3">
                  <label className="form-label">Subdomain</label>
                  <div className="input-group">
                    <input type="text" className={`form-control ${errors.subdomain ? 'is-invalid' : ''}`} name="subdomain" value={formData.subdomain} onChange={handleChange} />
                    <span className="input-group-text">.yourapp.com</span>
                  </div>
                  {errors.subdomain && <div className="invalid-feedback d-block">{errors.subdomain}</div>}
                </div>
                <div className="mb-3">
                  <label className="form-label">Admin Full Name</label>
                  <input type="text" className={`form-control ${errors.adminFullName ? 'is-invalid' : ''}`} name="adminFullName" value={formData.adminFullName} onChange={handleChange} />
                  {errors.adminFullName && <div className="invalid-feedback d-block">{errors.adminFullName}</div>}
                </div>
                <div className="mb-3">
                  <label className="form-label">Admin Email</label>
                  <input type="email" className={`form-control ${errors.adminEmail ? 'is-invalid' : ''}`} name="adminEmail" value={formData.adminEmail} onChange={handleChange} />
                  {errors.adminEmail && <div className="invalid-feedback d-block">{errors.adminEmail}</div>}
                </div>
                <div className="mb-3">
                  <label className="form-label">Password</label>
                  <input type="password" className={`form-control ${errors.adminPassword ? 'is-invalid' : ''}`} name="adminPassword" value={formData.adminPassword} onChange={handleChange} />
                  {errors.adminPassword && <div className="invalid-feedback d-block">{errors.adminPassword}</div>}
                </div>
                <div className="mb-3">
                  <label className="form-label">Confirm Password</label>
                  <input type="password" className={`form-control ${errors.confirmPassword ? 'is-invalid' : ''}`} name="confirmPassword" value={formData.confirmPassword} onChange={handleChange} />
                  {errors.confirmPassword && <div className="invalid-feedback d-block">{errors.confirmPassword}</div>}
                </div>
                <button type="submit" className="btn btn-primary w-100" disabled={loading}>{loading ? 'Registering...' : 'Register'}</button>
              </form>
              <p className="text-center mt-3">Already have an account? <a href="/login">Login</a></p>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};

export default Register;
