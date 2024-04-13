const mongoose = require('mongoose');

const employeeSchema = new mongoose.Schema({
    name: {
        type: String,
        required: true,
        minlength: 2,
        maxlength: 50 // Example minimum and maximum lengths
    },
    designation: {
        type: String,
        enum: ['Manager', 'Developer', 'Designer'] // Example enum validation for role
    },
    role: {
        type: String,
        required: false,
        default: "employee"
        // enum: ['Manager', 'Developer', 'Designer'] // Example enum validation for role
    },
    email: {
        type: String,
        required: true,
        unique: true, // Ensure uniqueness
        match: /^\S+@\S+\.\S+$/ // Example email format validation
    },
   
    username: {
        type: String,
        required: true,
        unique: true // Ensure uniqueness
    },
    password: {
        type: String,
        required: true,
        minlength: 6 // Example minimum length for password
    },
    // Additional fields can be added here
    // dateOfBirth: { type: Date },
    // dateOfEmployment: { type: Date }
});

// Hash the password before saving
const bcrypt = require('bcrypt');
employeeSchema.pre('save', async function (next) {
    if (!this.isModified('password')) return next();
    try {
        // Generate a hash of the password
        const salt = await bcrypt.genSalt(10);
        const hash = await bcrypt.hash(this.password, salt);
        this.password = hash;
        next();
    } catch (error) {
        next(error);
    }
});

module.exports = mongoose.model('Employee', employeeSchema);
