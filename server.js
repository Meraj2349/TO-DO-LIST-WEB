const express = require('express');
const mysql = require('mysql');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');


const app = express();
app.use(express.json());

// MySQL connection setup
const connection = mysql.createConnection({
    user: 'root',
    host: 'localhost',
    password: '',
    database: 'todolist',
    
  });



connection.connect((err) => {
    if (err) {
        console.error('Error connecting to MySQL:', err);
        return;
    }
    console.log('Connected to MySQL database');
});

// Middleware for authentication
function authenticateToken(req, res, next) {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    if (token == null) {
        return res.sendStatus(401);
    }

    jwt.verify(token, 'your_secret_key', (err, user) => {
        if (err) {
            return res.sendStatus(403);
        }
        req.user = user;
        next();
    });
}

// Routes for user registration and login
app.post('/register', (req, res) => {
    const { username, email, password } = req.body;
    // Hash the password using bcrypt
    const hashedPassword = bcrypt.hashSync(password, 10);

    // Insert the user into the database
    const sql = 'INSERT INTO users (username, email, password) VALUES (?, ?, ?)';
    connection.query(sql, [username, email, hashedPassword], (err, result) => {
        if (err) {
            console.error('Error registering user:', err);
            return res.sendStatus(500);
        }
        res.sendStatus(201);
    });
});

app.post('/login', (req, res) => {
    const { username, password } = req.body;

    // Retrieve the user from the database
    const sql = 'SELECT * FROM users WHERE username = ?';
    connection.query(sql, [username], (err, results) => {
        if (err) {
            console.error('Error logging in:', err);
            return res.sendStatus(500);
        }

        if (results.length === 0) {
            return res.sendStatus(401);
        }

        const user = results[0];
        // Compare the provided password with the hashed password
        const passwordMatch = bcrypt.compareSync(password, user.password);
        if (!passwordMatch) {
            return res.sendStatus(401);
        }

        // Generate a JWT token
        const token = jwt.sign({ id: user.id, username: user.username }, 'your_secret_key');
        res.json({ token });
    });
});

// Protected route example
app.get('/tasks', authenticateToken, (req, res) => {
    const userId = req.user.id;
    const sql = 'SELECT * FROM tasks WHERE user_id = ?';
    connection.query(sql, [userId], (err, results) => {
        if (err) {
            console.error('Error retrieving tasks:', err);
            return res.sendStatus(500);
        }
        res.json(results);
    });
});

// Start the server
app.listen(3000, () => {
    console.log('Server started on port 3000');
});