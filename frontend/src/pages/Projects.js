import React, { useState, useEffect, useContext } from 'react';
import { AuthContext } from '../context/AuthContext';
import api from '../services/api';

const Projects = () => {
  const { user } = useContext(AuthContext);
  const [projects, setProjects] = useState([]);
  const [loading, setLoading] = useState(true);
  const [showModal, setShowModal] = useState(false);
  const [formData, setFormData] = useState({ name: '', description: '' });
  const [error, setError] = useState('');

  useEffect(() => {
    fetchProjects();
  }, []);

  const fetchProjects = async () => {
    try {
      const response = await api.get('/projects');
      setProjects(response.data.data.projects || []);
    } catch (error) {
      console.error('Failed to fetch projects:', error);
      setError(error.response?.data?.message || 'Failed to load projects');
    } finally {
      setLoading(false);
    }
  };

  const handleCreate = async (e) => {
    e.preventDefault();
    if (!formData.name) {
      setError('Project name is required');
      return;
    }
    try {
      await api.post('/projects', formData);
      setFormData({ name: '', description: '' });
      setShowModal(false);
      fetchProjects();
    } catch (error) {
      setError(error.response?.data?.message || 'Failed to create project');
    }
  };

  const handleDelete = async (projectId) => {
    if (window.confirm('Are you sure?')) {
      try {
        await api.delete(`/projects/${projectId}`);
        fetchProjects();
      } catch (error) {
        setError('Failed to delete project');
      }
    }
  };

  if (loading) return <div className="container mt-5"><p>Loading...</p></div>;

  return (
    <div className="container mt-5 mb-5">
      <div className="d-flex justify-content-between align-items-center mb-4">
        <h1>Projects</h1>
        <button className="btn btn-primary" onClick={() => setShowModal(true)}>Create Project</button>
      </div>

      {error && <div className="alert alert-danger">{error}</div>}

      <div className="row">
        {projects.map(p => (
          <div key={p.id} className="col-md-6 col-lg-4 mb-3">
            <div className="card h-100">
              <div className="card-body">
                <h5 className="card-title">{p.name}</h5>
                <p className="card-text text-muted">{p.description}</p>
                <div className="d-flex justify-content-between align-items-center">
                  <span className={`badge bg-${p.status === 'active' ? 'success' : 'secondary'}`}>{p.status}</span>
                  <small>{p.taskCount || 0} tasks</small>
                </div>
              </div>
              <div className="card-footer bg-white">
                <button className="btn btn-sm btn-primary" onClick={() => window.location.href = `/projects/${p.id}`}>View</button>
                {user?.role === 'tenant_admin' && (
                  <button className="btn btn-sm btn-danger float-end" onClick={() => handleDelete(p.id)}>Delete</button>
                )}
              </div>
            </div>
          </div>
        ))}
      </div>

      {showModal && (
        <div className="modal d-block" style={{ backgroundColor: 'rgba(0,0,0,0.5)' }}>
          <div className="modal-dialog">
            <div className="modal-content">
              <div className="modal-header">
                <h5 className="modal-title">Create Project</h5>
                <button type="button" className="btn-close" onClick={() => setShowModal(false)}></button>
              </div>
              <form onSubmit={handleCreate}>
                <div className="modal-body">
                  <div className="mb-3">
                    <label className="form-label">Project Name</label>
                    <input type="text" className="form-control" value={formData.name} onChange={(e) => setFormData({...formData, name: e.target.value})} />
                  </div>
                  <div className="mb-3">
                    <label className="form-label">Description</label>
                    <textarea className="form-control" rows="3" value={formData.description} onChange={(e) => setFormData({...formData, description: e.target.value})}></textarea>
                  </div>
                </div>
                <div className="modal-footer">
                  <button type="button" className="btn btn-secondary" onClick={() => setShowModal(false)}>Cancel</button>
                  <button type="submit" className="btn btn-primary">Create</button>
                </div>
              </form>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

export default Projects;
