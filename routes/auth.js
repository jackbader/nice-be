const express = require('express');
const router = express.Router();
const bcrypt = require('bcrypt');
const { body, validationResult } = require('express-validator');
const db = require('../db');

// Validation middleware
const validateSignup = [
    body('email').isEmail().normalizeEmail(),
    body('password').isLength({ min: 6 })
];

const validateLogin = [
    body('email').isEmail().normalizeEmail(),
    body('password').exists()
];

// Error handling middleware for this router
const asyncHandler = (fn) => (req, res, next) => {
    Promise.resolve(fn(req, res, next)).catch(next);
};
// Verify session and return user data
router.get('/verify', asyncHandler(async (req, res) => {
    // If no active session, return unauthorized
    if (!req.session.userId) {
        return res.status(401).json({ error: 'Not authenticated' });
    }

    // Get fresh user data from database
    const user = await db('users')
        .where({ id: req.session.userId })
        .first();

    if (!user) {
        // Clear invalid session and return unauthorized
        req.session.destroy();
        return res.status(401).json({ error: 'User not found' });
    }

    // Return user data
    res.json({
        user: {
            id: user.id,
            email: user.email
        }
    });
}));

// Signup route
router.post('/signup', validateSignup, asyncHandler(async (req, res) => {
    console.log('Signup request received:', { email: req.body.email });

    // Check for validation errors
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        console.log('Validation errors:', errors.array());
        return res.status(400).json({ errors: errors.array() });
    }

    const { email, password } = req.body;

    // Check if user already exists
    const existingUser = await db('users')
        .where({ email })
        .first();

    if (existingUser) {
        console.log('User already exists:', email);
        return res.status(400).json({ error: 'Email already registered' });
    }

    // Hash password
    const salt = await bcrypt.genSalt(10);
    const passwordHash = await bcrypt.hash(password, salt);

    // Create user
    const [user] = await db('users')
        .insert({
            email,
            password_hash: passwordHash
        })
        .returning(['id', 'email']);

    // Set session
    req.session.userId = user.id;
    req.session.email = user.email;

    console.log('User created successfully:', { id: user.id, email: user.email });
    res.status(201).json({
        message: 'User created successfully',
        user: {
            id: user.id,
            email: user.email
        }
    });
}));

// Login route
router.post('/login', validateLogin, asyncHandler(async (req, res) => {

    // Check for validation errors
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        console.log('Validation errors:', errors.array());
        return res.status(400).json({ errors: errors.array() });
    }

    const { email, password } = req.body;

    // Find user
    const user = await db('users')
        .where({ email })
        .first();

    if (!user) {
        console.log('Login failed: User not found:', email);
        return res.status(401).json({ error: 'Invalid credentials' });
    }

    // Verify password
    const validPassword = await bcrypt.compare(password, user.password_hash);
    if (!validPassword) {
        console.log('Login failed: Invalid password for user:', email);
        return res.status(401).json({ error: 'Invalid credentials' });
    }

    // Regenerate session to prevent session fixation
    req.session.regenerate(async (err) => {
        if (err) {
            console.error('Error regenerating session:', err);
            return res.status(500).json({ error: 'Error creating session' });
        }

        // Set session data
        req.session.userId = user.id;
        req.session.email = user.email;

        // Save session
        req.session.save((err) => {
            if (err) {
                console.error('Error saving session:', err);
                return res.status(500).json({ error: 'Error creating session' });
            }

            console.log('Session after save:', {
                sessionID: req.sessionID,
                session: {
                    id: req.session.id,
                    userId: req.session.userId,
                    email: req.session.email
                },
                cookies: req.headers.cookie
            });

            // Send response
            res.json({
                message: 'Login successful',
                user: {
                    id: user.id,
                    email: user.email
                }
            });
        });
    });
}));

// Logout route
router.post('/logout', asyncHandler(async (req, res) => {
    console.log('Logout request received:', {
        sessionID: req.sessionID,
        cookies: req.headers.cookie,
        session: req.session ? {
            id: req.session.id,
            userId: req.session.userId,
            email: req.session.email
        } : 'no session'
    });

    if (!req.session) {
        console.log('No session to destroy');
        return res.json({ message: 'Already logged out' });
    }

    // Get the session ID before destroying
    const sessionId = req.sessionID;

    // Destroy the session
    req.session.destroy(async (err) => {
        if (err) {
            console.error('Error destroying session:', err);
            return res.status(500).json({ error: 'Error logging out' });
        }

        try {
            // Also remove from database
            await db('sessions')
                .where('sid', sessionId)
                .del();

            console.log('Session removed from database:', sessionId);
        } catch (dbErr) {
            console.error('Error removing session from database:', dbErr);
            // Continue with logout even if database cleanup fails
        }

        // Clear the session cookie
        res.clearCookie('connect.sid', {
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production',
            sameSite: 'lax',
            path: '/'
        });

        console.log('Logout successful');
        res.json({ message: 'Logged out successfully' });
    });
}));

// Error handling middleware
router.use((err, req, res, next) => {
    console.error('Auth route error:', err);
    res.status(500).json({
        error: 'Internal server error',
        message: err.message
    });
});

module.exports = router; 