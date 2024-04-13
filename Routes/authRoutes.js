const express = require('express');
const router = express.Router();
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const config = require('../Config/config');
const User = require('../Model/user'); // Import the User model if you have one

// Register a new admin user
router.post('/register', async (req, res) => {
    const { email, password, role } = req.body;
    try {
        // Check if the email already exists
        const existingUser = await User.findOne({ email });
        if (existingUser) {
            return res.status(400).json({ message: 'Email already exists' });
        }

        // Hash the password
        const salt = await bcrypt.genSalt(10);
        const hashedPassword = await bcrypt.hash(password, salt);

        // Create a new user instance
        const newUser = new User({
            email,
            password: hashedPassword,
            role: role || 'employee' // Default role is 'employee'
        });

        // Save the user to the database
        await newUser.save();

        res.status(201).json({ message: 'Admin user added successfully', user: newUser });
    } catch (error) {
        console.error(error);
        res.status(500).json({ message: 'Server error' });
    }
});

// Login user
router.post('/login', async (req, res) => {
    const { email, password } = req.body;
    try {
        // Find the user by email
        const user = await User.findOne({ email });
        if (!user) {
            return res.status(400).json({ message: 'Invalid credentials' });
        }

        // Compare passwords
        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) {
            return res.status(400).json({ message: 'Invalid credentials' });
        }

        // Generate JWT token
        const payload = {
            user: {
                id: user.id,
                role: user.role
            }
        };
        jwt.sign(payload, config.secret, { expiresIn: '1h' }, (err, token) => {
            if (err) throw err;
            res.json({ token, isAdmin: user.role === 'admin' });
        });
    } catch (error) {
        console.error(error);
        res.status(500).json({ message: 'Server error' });
    }
});

module.exports = router;
