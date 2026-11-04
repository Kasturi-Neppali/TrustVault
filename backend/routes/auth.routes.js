
const express = require('express');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const { User } = require('../models');
const { logAction } = require('../utils/audit');

const router = express.Router();

// [POST] /api/auth/register
// In a real system, registration might be locked down, but we need it to create test users (Admin, Owner, Viewer)
router.post('/register', async (req, res) => {
    try {
        const { email, password, role } = req.body;

        // Ensure the email isn't already taken
        const existingUser = await User.findOne({ email });
        if (existingUser) {
            return res.status(400).json({ error: 'Email already registered.' });
        }

        // Hash the password
        const salt = await bcrypt.genSalt(10);
        const passwordHash = await bcrypt.hash(password, salt);

        // Create the user
        const newUser = new User({
            email,
            passwordHash,
            role: role || 'user' // Default to user (who can become an owner by uploading)
        });

        await newUser.save();

        res.status(201).json({ message: 'User created successfully.', userId: newUser._id });
    } catch (error) {
        console.error("Registration Error:", error);
        res.status(500).json({ error: 'Server error during registration.' });
    }
});

// [POST] /api/auth/login
router.post('/login', async (req, res) => {
    try {
        const { email, password } = req.body;

        // Find the user
        const user = await User.findOne({ email });
        if (!user) {
            return res.status(401).json({ error: 'Invalid email or password.' });
        }

        // Check the password
        const validPassword = await bcrypt.compare(password, user.passwordHash);
        if (!validPassword) {
            return res.status(401).json({ error: 'Invalid email or password.' });
        }

        // Issue JWT - NOTE: We ONLY put the userId in the token. 
        // This forces the "Immediate Revocation" check in the database later.
        const token = jwt.sign(
            { userId: user._id, role: user.role },
            process.env.JWT_SECRET,
            { expiresIn: '8h' }
        );

        // Audit Log: Record the successful login
        await logAction({
            actorId: user._id,
            action: 'login',
            status: 'success',
            ipAddress: req.ip
        });

        res.json({
            message: 'Logged in successfully.',
            token,
            user: { id: user._id, email: user.email, role: user.role }
        });
    } catch (error) {
        console.error("Login Error:", error);
        res.status(500).json({ error: 'Server error during login.' });
    }
});

module.exports = router;