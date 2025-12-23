const express = require('express');
const { createProject, listProjects, updateProject, deleteProject } = require('../controllers/projectController');
const { authenticateToken } = require('../middleware/auth');

const router = express.Router();

router.post('/', authenticateToken, createProject);
router.get('/', authenticateToken, listProjects);
router.put('/:projectId', authenticateToken, updateProject);
router.delete('/:projectId', authenticateToken, deleteProject);

module.exports = router;
