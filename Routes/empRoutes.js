const express = require('express');
const router = express.Router();
const employeeController = require('../Controllers/empController');
const authMiddleware = require('../Middleware/authMiddleware');

// Routes for CRUD operations on Employees

// Create a new Employee
router.post('/', authMiddleware.authenticateUser, authMiddleware.checkAdminRole, employeeController.createEmployee);

// Get all Employees
router.get('/view', authMiddleware.authenticateUser, employeeController.getAllEmployees);

// Get Employee by ID
router.get('/:id', authMiddleware.authenticateUser, employeeController.getEmployeeById);

// Update Employee by ID
router.put('/:id', authMiddleware.authenticateUser, authMiddleware.checkAdminRole, employeeController.updateEmployee);

// Delete Employee by ID
router.delete('/:id', authMiddleware.authenticateUser, authMiddleware.checkAdminRole, employeeController.deleteEmployee);

module.exports = router;
