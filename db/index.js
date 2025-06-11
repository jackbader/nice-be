const knex = require('knex');
const config = require('../knexfile');

// Use the environment from NODE_ENV or default to development
const environment = process.env.NODE_ENV || 'development';
const db = knex(config[environment]);

// Test the connection
db.raw('SELECT 1')
    .then(() => {
        console.log('Database connection successful');
    })
    .catch((err) => {
        console.error('Database connection failed:', err);
    });

module.exports = db; 