const express = require('express');
const cors = require('cors');
const session = require('express-session');
const pgSession = require('connect-pg-simple')(session);
require('dotenv').config();
const db = require('./db');
const authRoutes = require('./routes/auth');

const app = express();
const port = process.env.PORT || 8000;

// CORS configuration
const corsOptions = {
    origin: process.env.FRONTEND_URL || 'http://localhost:3000',
    credentials: true,
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization']
};

// Middleware
app.use(cors(corsOptions));
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Session configuration
const sessionStore = new pgSession({
    conObject: {
        host: process.env.DB_HOST || 'localhost',
        port: process.env.DB_PORT || 5432,
        database: process.env.DB_NAME || 'nice_db',
        user: process.env.DB_USER || 'postgres',
        password: process.env.DB_PASSWORD || 'postgres'
    },
    tableName: 'sessions',
    createTableIfMissing: true,
    pruneSessionInterval: 60, // Prune expired sessions every 60 seconds
    errorCallback: (err) => {
        console.error('Session store error:', err);
    }
});

app.use(session({
    store: sessionStore,
    secret: process.env.SESSION_SECRET || 'your-secret-key',
    resave: false, // Changed to false as we're using rolling sessions
    rolling: true, // Refresh session on activity
    saveUninitialized: false,
    name: 'connect.sid',
    cookie: {
        secure: process.env.NODE_ENV === 'production',
        httpOnly: true,
        maxAge: 24 * 60 * 60 * 1000, // 24 hours
        sameSite: 'lax',
        path: '/'
    },
    genid: function (req) {
        // Generate a unique session ID
        const sessionId = require('crypto').randomBytes(32).toString('hex');
        console.log('Generated new session ID:', sessionId);
        return sessionId;
    }
}));

// Routes
app.use('/auth', authRoutes);

// Basic route
app.get('/', (req, res) => {
    res.json({ message: 'Welcome to the Express application!' });
});

// Health check route
app.get('/health', (req, res) => {
    res.json({ status: 'ok' });
});

// Test database connection route
app.get('/db-test', async (req, res, next) => {
    try {
        const result = await db.raw('SELECT NOW()');
        res.json({
            message: 'Database connection successful',
            timestamp: result.rows[0].now
        });
    } catch (err) {
        next(err);
    }
});

// 404 handler
app.use((req, res) => {
    res.status(404).json({
        error: 'Not Found',
        message: `Cannot ${req.method} ${req.path}`
    });
});

// Error handling middleware
app.use((err, req, res, next) => {
    // Prevent multiple error responses
    if (res.headersSent) {
        return next(err);
    }

    console.error('Global error:', err);

    // Handle JSON parsing errors
    if (err instanceof SyntaxError && err.status === 400 && 'body' in err) {
        return res.status(400).json({
            error: 'Bad Request',
            message: 'Invalid JSON in request body'
        });
    }

    res.status(err.status || 500).json({
        error: err.name || 'Internal Server Error',
        message: err.message || 'Something went wrong'
    });
});

// Start server
app.listen(port, () => {
    console.log(`Server is running on port ${port}`);
}); 