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
    console.log('Verify request received', {
        sessionID: req.sessionID,
        cookies: req.headers.cookie,
        session: req.session ? {
            id: req.session.id,
            userId: req.session.userId,
            email: req.session.email
        } : 'no session'
    });

    // Extract session ID from cookie if not in req.sessionID
    let sessionId = req.sessionID;
    if (!sessionId && req.headers.cookie) {
        const cookies = req.headers.cookie.split(';');
        const sessionCookie = cookies.find(cookie => cookie.trim().startsWith('connect.sid='));
        if (sessionCookie) {
            sessionId = sessionCookie.split('=')[1].trim();
            // Remove the 's:' prefix and everything after the first dot if present
            sessionId = sessionId.replace(/^s:/, '').split('.')[0];
            console.log('Extracted session ID from cookie:', sessionId);
        }
    }

    // Check session in database
    try {
        const dbSession = await db('sessions')
            .where('sid', sessionId)
            .first();


        if (dbSession) {
            // The session data is already an object, no need to parse
            const sessionData = dbSession.sess;

            // If session exists in database but not in memory, restore it
            if (!req.session.userId && sessionData.userId) {
                console.log('Restoring session from database');
                Object.assign(req.session, {
                    userId: sessionData.userId,
                    email: sessionData.email
                });
                await new Promise((resolve, reject) => {
                    req.session.save(err => {
                        if (err) {
                            console.error('Error saving restored session:', err);
                            reject(err);
                        } else {
                            console.log('Session restored successfully');
                            resolve();
                        }
                    });
                });
            }
        } else {
            console.log('No session found in database for ID:', sessionId);
        }
    } catch (err) {
        console.error('Error checking session in database:', err);
    }

    if (!req.session.userId) {
        console.log('No active session found in memory');
        return res.status(401).json({ error: 'Not authenticated' });
    }

    try {
        console.log('Session found, fetching user data for:', req.session.userId);

        // Get fresh user data from database
        const user = await db('users')
            .where({ id: req.session.userId })
            .first();

        if (!user) {
            console.log('User not found for id:', req.session.userId);
            // Clear invalid session
            req.session.destroy();
            return res.status(401).json({ error: 'User not found' });
        }

        console.log('User verified successfully:', { id: user.id, email: user.email });
        res.json({
            user: {
                id: user.id,
                email: user.email
            }
        });
    } catch (error) {
        console.error('Error verifying session:', error);
        throw error;
    }
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
    console.log('Login request received:', {
        email: req.body.email,
        cookies: req.headers.cookie,
        sessionID: req.sessionID,
        headers: req.headers
    });

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