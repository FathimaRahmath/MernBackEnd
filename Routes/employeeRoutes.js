const express = require("express");
const router = express.Router();
const Employee = require("../Model/employee");
const jwt = require('jsonwebtoken');

router.use(express.json());
router.use(express.urlencoded({ extended: true }));

// Authentication middleware to verify JWT token
function verifyToken(req, res, next) {
    const token = req.headers.token;
    try {
        if (!token) throw 'Unauthorized access';
        let payload = jwt.verify(token, 'reactempapp');
        if (!payload) throw 'Unauthorized access';
        if (payload.role !== 'admin') throw 'Unauthorized access: Admin role required';
        next();
    } catch (error) {
        res.status(401).send({ error: 'Unauthorized access' });
    }
}

// Create employee
router.post('/add',   async (req, res) => {
    try {
        
        const employeeData = req.body;
        const newEmployee = await Employee.create(employeeData);
        res.status(201).json({ message: 'Employee added successfully', employee: newEmployee });
    } catch (error) {
        console.error(error);
        res.status(500).json({ error: 'Server error' });
    }
});

// Read all employees verifyToken,
router.get('/view',  async (req, res) => {
    try {
        const employees = await Employee.find();
        res.status(200).json(employees);
    } catch (error) {
        console.error(error);
        res.status(500).json({ error: 'Server error' });
    }
});

// Update employee by ID  verifyToken,
router.put('/:id', async (req, res) => {
    try {
        const { id } = req.params;
        const updatedEmployee = await Employee.findByIdAndUpdate(id, req.body, { new: true });
        res.status(200).json({ message: 'Employee updated successfully', employee: updatedEmployee });
    } catch (error) {
        console.error(error);
        res.status(500).json({ error: 'Server error' });
    }
});

// Delete employee by ID verifyToken,
router.delete('/:id',  async (req, res) => {
    try {
        const { id } = req.params;
        await Employee.findByIdAndDelete(id);
        res.status(200).json({ message: 'Employee deleted successfully' });
    } catch (error) {
        console.error(error);
        res.status(500).json({ error: 'Server error' });
    }
});

module.exports = router;
