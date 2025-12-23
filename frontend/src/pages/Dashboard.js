import React, { useState, useEffect, useContext } from 'react';
import { AuthContext } from '../context/AuthContext';
import api from '../services/api';

const Dashboard = () => {
  const { user } = useContext(AuthContext);
  const [stats, setStats] = useState({ projects: 0, tasks: 0, completed: 0, pending: 0 });
  const [recentProjects, setRecentProjects] = useState([]);
  const [myTasks, setMyTasks] = useState([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    fetchDashboardData();
  }, []);

  const fetchDashboardData = async () => {
    try {
      const [projectsRes, tasksRes] = await Promise.all([
        api.get('/projects?limit=5'),
        api.get(`/projects/tasks?assignedTo=${user?.id}`)
      ]);

      const projects = projectsRes.data.data.projects || [];
      const tasks = tasksRes.data.data.tasks || [];

      setRecentProjects(projects);
      setMyTasks(tasks.filter(t => t.assignedTo?.id === user?.id));

      setStats({
        projects: projectsRes.data.data.total || 0,
        tasks: projects.reduce((sum, p) => sum + (p.taskCount || 0), 0),
        completed: projects.reduce((sum, p) => sum + (p.completedTaskCount || 0), 0),
        pending: tasks.filter(t => t.status !== 'completed').length
      });
    } catch (error) {
      console.error('Failed to fetch dashboard data:', error);
    } finally {
      setLoading(false);
    }
  };

  if (loading) return <div className="container mt-5"><p>Loading...</p></div>;

  return (
    <div className="container mt-5 mb-5">
      <h1 className="mb-4">Dashboard</h1>
      
      <div className="row mb-4">
        <div className="col-md-3">
          <div className="stat-card">
            <div className="stat-value">{stats.projects}</div>
            <div className="stat-label">Total Projects</div>
          </div>
        </div>
        <div className="col-md-3">
          <div className="stat-card">
            <div className="stat-value">{stats.tasks}</div>
            <div className="stat-label">Total Tasks</div>
          </div>
        </div>
        <div className="col-md-3">
          <div className="stat-card">
            <div className="stat-value">{stats.completed}</div>
            <div className="stat-label">Completed Tasks</div>
          </div>
        </div>
        <div className="col-md-3">
          <div className="stat-card">
            <div className="stat-value">{stats.pending}</div>
            <div className="stat-label">Pending Tasks</div>
          </div>
        </div>
      </div>

      <div className="row">
        <div className="col-md-6">
          <div className="card">
            <div className="card-header bg-primary text-white">Recent Projects</div>
            <div className="card-body">
              {recentProjects.length > 0 ? (
                <ul className="list-group list-group-flush">
                  {recentProjects.map(p => (
                    <li key={p.id} className="list-group-item">
                      <div className="d-flex justify-content-between align-items-center">
                        <div>
                          <h6 className="mb-1">{p.name}</h6>
                          <small className="text-muted">{p.taskCount} tasks</small>
                        </div>
                        <span className={`badge bg-${p.status === 'active' ? 'success' : 'secondary'}`}>{p.status}</span>
                      </div>
                    </li>
                  ))}
                </ul>
              ) : (
                <p className="text-muted">No projects yet</p>
              )}
            </div>
          </div>
        </div>

        <div className="col-md-6">
          <div className="card">
            <div className="card-header bg-primary text-white">My Tasks</div>
            <div className="card-body">
              {myTasks.length > 0 ? (
                <ul className="list-group list-group-flush">
                  {myTasks.slice(0, 5).map(t => (
                    <li key={t.id} className="list-group-item">
                      <div className="d-flex justify-content-between align-items-center">
                        <div>
                          <h6 className="mb-1">{t.title}</h6>
                          <small className="text-muted">Priority: {t.priority}</small>
                        </div>
                        <span className={`badge bg-${t.status === 'completed' ? 'success' : 'warning'}`}>{t.status}</span>
                      </div>
                    </li>
                  ))}
                </ul>
              ) : (
                <p className="text-muted">No assigned tasks</p>
              )}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};

export default Dashboard;
