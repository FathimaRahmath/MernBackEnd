const jwt = require('jsonwebtoken');
const config = require('../Config/config');

// Middleware for authentication and authorization
exports.authenticateUser = (req, res, next) => {
    const token = req.header('Authorization');
    if (!token) {
        return res.status(401).json({ message: 'No token, authorization denied' });
    }

    try {
        const decoded = jwt.verify(token, config.secret);
        req.user = decoded.user;
        next();
    } catch (error) {
        res.status(401).json({ message: 'Invalid token' });
    }
};

// Middleware for checking admin role
exports.checkAdminRole = (req, res, next) => {
    if (req.user.role !== 'admin') {
        return res.status(403).json({ message: 'Not authorized' });
    }
    next();
};
