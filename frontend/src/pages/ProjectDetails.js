import React, { useState, useEffect, useContext } from 'react';
import { useParams } from 'react-router-dom';
import { AuthContext } from '../context/AuthContext';
import api from '../services/api';

const ProjectDetails = () => {
  const { projectId } = useParams();
  const { user } = useContext(AuthContext);
  const [project, setProject] = useState(null);
  const [tasks, setTasks] = useState([]);
  const [loading, setLoading] = useState(true);
  const [showTaskModal, setShowTaskModal] = useState(false);
  const [taskFormData, setTaskFormData] = useState({ title: '', description: '', priority: 'medium' });

  useEffect(() => {
    fetchProjectDetails();
  }, [projectId]);

  const fetchProjectDetails = async () => {
    try {
      const [projectRes, tasksRes] = await Promise.all([
        api.get(`/projects/${projectId}`),
        api.get(`/projects/${projectId}/tasks`)
      ]);
      setProject(projectRes.data.data);
      setTasks(tasksRes.data.data.tasks || []);
    } catch (error) {
      console.error('Failed to fetch project details:', error);
    } finally {
      setLoading(false);
    }
  };

  const handleCreateTask = async (e) => {
    e.preventDefault();
    if (!taskFormData.title) return;
    try {
      await api.post(`/projects/${projectId}/tasks`, taskFormData);
      setTaskFormData({ title: '', description: '', priority: 'medium' });
      setShowTaskModal(false);
      fetchProjectDetails();
    } catch (error) {
      console.error('Failed to create task:', error);
    }
  };

  const handleTaskStatusChange = async (taskId, newStatus) => {
    try {
      await api.patch(`/tasks/${taskId}/status`, { status: newStatus });
      fetchProjectDetails();
    } catch (error) {
      console.error('Failed to update task:', error);
    }
  };

  if (loading) return <div className="container mt-5"><p>Loading...</p></div>;
  if (!project) return <div className="container mt-5"><p>Project not found</p></div>;

  return (
    <div className="container mt-5 mb-5">
      <div className="d-flex justify-content-between align-items-center mb-4">
        <div>
          <h1>{project.name}</h1>
          <p className="text-muted">{project.description}</p>
        </div>
        <button className="btn btn-primary" onClick={() => setShowTaskModal(true)}>Add Task</button>
      </div>

      <div className="card">
        <div className="card-header">Tasks ({tasks.length})</div>
        <div className="card-body">
          {tasks.length > 0 ? (
            <div className="table-responsive">
              <table className="table">
                <thead>
                  <tr>
                    <th>Title</th>
                    <th>Status</th>
                    <th>Priority</th>
                    <th>Assigned To</th>
                    <th>Actions</th>
                  </tr>
                </thead>
                <tbody>
                  {tasks.map(t => (
                    <tr key={t.id}>
                      <td>{t.title}</td>
                      <td>
                        <select className="form-select form-select-sm" value={t.status} onChange={(e) => handleTaskStatusChange(t.id, e.target.value)}>
                          <option value="todo">To Do</option>
                          <option value="in_progress">In Progress</option>
                          <option value="completed">Completed</option>
                        </select>
                      </td>
                      <td><span className={`badge bg-${t.priority === 'high' ? 'danger' : t.priority === 'medium' ? 'warning' : 'success'}`}>{t.priority}</span></td>
                      <td>{t.assignedTo?.fullName || '-'}</td>
                      <td>
                        <button className="btn btn-sm btn-danger" onClick={() => api.delete(`/tasks/${t.id}`).then(() => fetchProjectDetails())}>Delete</button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          ) : (
            <p className="text-muted">No tasks yet</p>
          )}
        </div>
      </div>

      {showTaskModal && (
        <div className="modal d-block" style={{ backgroundColor: 'rgba(0,0,0,0.5)' }}>
          <div className="modal-dialog">
            <div className="modal-content">
              <div className="modal-header">
                <h5 className="modal-title">Add Task</h5>
                <button type="button" className="btn-close" onClick={() => setShowTaskModal(false)}></button>
              </div>
              <form onSubmit={handleCreateTask}>
                <div className="modal-body">
                  <div className="mb-3">
                    <label className="form-label">Task Title</label>
                    <input type="text" className="form-control" value={taskFormData.title} onChange={(e) => setTaskFormData({...taskFormData, title: e.target.value})} />
                  </div>
                  <div className="mb-3">
                    <label className="form-label">Description</label>
                    <textarea className="form-control" rows="3" value={taskFormData.description} onChange={(e) => setTaskFormData({...taskFormData, description: e.target.value})}></textarea>
                  </div>
                  <div className="mb-3">
                    <label className="form-label">Priority</label>
                    <select className="form-select" value={taskFormData.priority} onChange={(e) => setTaskFormData({...taskFormData, priority: e.target.value})}>
                      <option value="low">Low</option>
                      <option value="medium">Medium</option>
                      <option value="high">High</option>
                    </select>
                  </div>
                </div>
                <div className="modal-footer">
                  <button type="button" className="btn btn-secondary" onClick={() => setShowTaskModal(false)}>Cancel</button>
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

export default ProjectDetails;
