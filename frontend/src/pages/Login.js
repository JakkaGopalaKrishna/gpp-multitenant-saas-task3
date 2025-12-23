import React, { useState, useContext } from 'react';
import { useNavigate } from 'react-router-dom';
import { AuthContext } from '../context/AuthContext';
import api from '../services/api';

const Login = () => {
  const navigate = useNavigate();
  const { login } = useContext(AuthContext);
  const [formData, setFormData] = useState({
    email: '',
    password: '',
    tenantSubdomain: ''
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

    if (!formData.email) newErrors.email = 'Email required';
    if (!formData.password) newErrors.password = 'Password required';
    if (!formData.tenantSubdomain) newErrors.tenantSubdomain = 'Subdomain required';

    if (Object.keys(newErrors).length > 0) {
      setErrors(newErrors);
      return;
    }

    setLoading(true);
    try {
      const response = await api.post('/auth/login', {
        email: formData.email,
        password: formData.password,
        tenantSubdomain: formData.tenantSubdomain
      });
      const { token, user } = response.data.data;
      login(token, user);
      navigate('/dashboard');
    } catch (error) {
      const errorMsg = error.response?.data?.message || 'Login failed';
      setMessage(errorMsg);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="container mt-5">
      <div className="row justify-content-center">
        <div className="col-md-5">
          <div className="card shadow">
            <div className="card-body p-4">
              <h2 className="card-title text-center mb-4">Login</h2>
              {message && <div className="alert alert-danger">{message}</div>}
              <form onSubmit={handleSubmit}>
                <div className="mb-3">
                  <label className="form-label">Subdomain</label>
                  <input type="text" className={`form-control ${errors.tenantSubdomain ? 'is-invalid' : ''}`} name="tenantSubdomain" value={formData.tenantSubdomain} onChange={handleChange} placeholder="demo" />
                  {errors.tenantSubdomain && <div className="invalid-feedback d-block">{errors.tenantSubdomain}</div>}
                </div>
                <div className="mb-3">
                  <label className="form-label">Email</label>
                  <input type="email" className={`form-control ${errors.email ? 'is-invalid' : ''}`} name="email" value={formData.email} onChange={handleChange} />
                  {errors.email && <div className="invalid-feedback d-block">{errors.email}</div>}
                </div>
                <div className="mb-3">
                  <label className="form-label">Password</label>
                  <input type="password" className={`form-control ${errors.password ? 'is-invalid' : ''}`} name="password" value={formData.password} onChange={handleChange} />
                  {errors.password && <div className="invalid-feedback d-block">{errors.password}</div>}
                </div>
                <button type="submit" className="btn btn-primary w-100" disabled={loading}>{loading ? 'Logging in...' : 'Login'}</button>
              </form>
              <p className="text-center mt-3">Don't have an account? <a href="/register">Register</a></p>
              <hr />
              <p className="text-muted small text-center">Demo: subdomain=demo, email=admin@demo.com, password=Demo@123</p>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};

export default Login;
