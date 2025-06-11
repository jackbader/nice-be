const db = require('../db');

const auth = async (req, res, next) => {
    try {
        if (!req.session.userId) {
            return res.status(401).json({ error: 'Authentication required' });
        }

        // Get fresh user data from database
        const user = await db('users')
            .where({ id: req.session.userId })
            .first();

        if (!user) {
            // Clear invalid session
            req.session.destroy();
            return res.status(401).json({ error: 'User not found' });
        }

        // Attach user data to request object
        req.user = {
            id: user.id,
            email: user.email
        };

        next();
    } catch (error) {
        console.error('Auth middleware error:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
};

module.exports = auth;
