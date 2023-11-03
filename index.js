const express = require('express');
const app = express();
const { v4: uuidv4 } = require('uuid');
const bcrypt = require("bcrypt");
const mysql = require('mysql2/promise');

require('dotenv').config();

const pool = mysql.createPool({
    host: process.env.DATABASE_HOSTNAME,
    user: process.env.DATABASE_USERNAME,
    password: process.env.DATABASE_PASSWORD,
    database: process.env.DATABASE_DATABASE,
});

const port = process.env.PORT || 3000;

// Serve static files
app.use(express.static('public'));

// Parse JSON bodies
app.use(express.json());

// General error handler
app.use((err, req, res, next) => {
    console.error(err.stack);
    const status = err.statusCode || 500;
    res.status(status).send(err.message);
})

// Middleware for authentication 
async function authorizeRequest(req, res, next) {
    // Validate authorization header exists
    if (!req.headers.authorization) {
        return res.status(401).send({ error: 'Authorization header is required' });
    }

    // Validate authorization header format
    const parts = req.headers.authorization.split(' ');
    if (parts.length !== 2 || parts[0] !== 'Bearer') {
        return res.status(401).send({ error: 'Authorization header format is Bearer {token}' });
    }

    // Get session token
    const token = parts[1];

    // Check the session in the sessions table
    const [rows] = await pool.query('SELECT * FROM sessions WHERE id = ?', [token]);

    if (rows.length === 0) {
        return res.status(401).send({ error: 'Invalid token' });
    }

    const session = rows[0];

    // Find the associated account
    const [accountRows] = await pool.query('SELECT * FROM accounts WHERE id = ?', [session.accountId]);

    if (accountRows.length === 0) {
        return res.status(401).send({ error: 'Invalid token' });
    }

    // Attach the session to the request
    req.session = session;

    // Continue
    next();
}

// Create account
app.post('/accounts', async (req, res) => {
    const { name, password } = req.body;

    if (!name || !password) {
        return res.status(400).send({ error: 'Please enter a name and password to sign up' });
    }

    // Check if an account with the same name already exists
    const [existingAccounts] = await pool.query('SELECT * FROM accounts WHERE name = ?', [name]);

    if (existingAccounts.length > 0) {
        return res.status(409).send({ error: 'An account with this name already exists' });
    }

    const hash = await bcrypt.hash(password, 10);
    const [result] = await pool.query('INSERT INTO accounts (name, password) VALUES (?, ?)', [name, hash]);
    const account = {
        id: result.insertId,
        name,
    };
    res.status(201).json(account);
});

// Login
app.post('/sessions', async (req, res) => {
    const { name, password } = req.body;

    if (!name || !password) {
        return res.status(400).send({ error: 'A name and password are required to sign in' });
    }

    const [rows] = await pool.query('SELECT * FROM accounts WHERE name = ?', [name]);

    if (rows.length === 0) {
        return res.status(404).send({ error: 'Account does not exist' });
    }

    const account = rows[0];

    const passwordMatch = await bcrypt.compare(password, account.password);

    if (!passwordMatch) {
        return res.status(401).send({ error: 'Wrong password' });
    }

    const sessionId = uuidv4();

    // Store the session in the sessions table
    await pool.query('INSERT INTO sessions (id, accountId) VALUES (?, ?)', [sessionId, account.id]);

    const session = {
        sessionId: sessionId,
    };

    res.status(201).json(session);
});

// Logout
app.delete('/sessions', authorizeRequest, async (req, res) => {
    try {
        // Delete the session from the sessions table
        await pool.query('DELETE FROM sessions WHERE id = ?', [req.session.id]);

        res.status(204).end();
    } catch (error) {
        console.error('Error deleting session:', error);
        res.status(500).send({ error: 'Internal Server Error' });
    }
});

// Select names from accounts database table
app.get('/names', authorizeRequest, async (req, res) => {
    const [rows] = await pool.query('SELECT name FROM accounts');

    if (rows.length === 0) {
        return res.status(404).send({ error: 'Account names not found' });
    }

    res.status(201).json(rows);
});


// Start server
app.listen(port, () => {
    console.log(`App running at http://localhost:${port}`);
})