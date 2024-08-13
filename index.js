const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcrypt');
const crypto = require('crypto');
const bodyParser = require('body-parser');

const app = express();
app.use(bodyParser.json());


const db = new sqlite3.Database('./users.db');
const pollution_db = new sqlite3.Database('./city_pollution.db');


db.run(`CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT,
  email TEXT UNIQUE,
  password TEXT,
  token TEXT
)`);
pollution_db.run(`CREATE TABLE IF NOT EXISTS city_pollution (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT,
    state TEXT,
    country TEXT,
    pm2_5 REAL,
    pm10 REAL,
    no2 REAL,
    so2 REAL,
    co REAL,
    o3 REAL,
    date TEXT
)`);


function generateToken() {
    return crypto.randomBytes(32).toString('hex');
}


function authenticateToken(req, res, next) {
    const token = req.headers['authorization'];

    if (!token) return res.sendStatus(401);

    db.get('SELECT * FROM users WHERE token = ?', [token], (err, user) => {
        if (err) return res.sendStatus(500);
        if (!user) return res.sendStatus(403);

        req.user = user;
        next();
    });
}


function validateToken(req, res, next) {
    const token = req.headers['authorization'];

    if (!token) return res.json({ isValid: false });

    db.get('SELECT 1 FROM users WHERE token = ?', [token], (err, user) => {
        if (err) return res.json({ isValid: false });
        if (!user) return res.json({ isValid: false });

        next();
    });
}


app.post('/register', async (req, res) => {
    const { name, email, password } = req.body;

    try {
        
        db.get('SELECT * FROM users WHERE email = ?', [email], async (err, row) => {
            if (err) {
                return res.status(500).json({ error: 'Database error' });
            }
            if (row) {
                return res.status(400).json({ error: 'User already exists' });
            }

            
            const hashedPassword = await bcrypt.hash(password, 10);

            
            db.run('INSERT INTO users (name, email, password) VALUES (?, ?, ?)', [name, email, hashedPassword], (err) => {
                if (err) {
                    return res.status(500).json({ error: 'Error creating user' });
                }
                res.status(201).json({ message: 'User created successfully' });
            });
        });
    } catch (error) {
        res.status(500).json({ error: 'Server error' });
    }
});


app.post('/login', (req, res) => {
    const { email, password } = req.body;

    db.get('SELECT * FROM users WHERE email = ?', [email], async (err, user) => {
        if (err) {
            return res.status(500).json({ error: 'Database error' });
        }
        if (!user) {
            return res.status(404).json({ error: 'User not found' });
        }

        try {
            if (await bcrypt.compare(password, user.password)) {
                const token = generateToken();
                db.run('UPDATE users SET token = ? WHERE id = ?', [token, user.id], (err) => {
                    if (err) {
                        return res.status(500).json({ error: 'Error updating token' });
                    }
                    res.json({ token });
                });
            } else {
                res.status(400).json({ error: 'Invalid credentials' });
            }
        } catch (error) {
            res.status(500).json({ error: 'Server error' });
        }
    });
});


app.get('/protected', authenticateToken, (req, res) => {
    res.json({ message: 'This is a protected route', user: { id: req.user.id, email: req.user.email } });
});


app.get('/validate-token', validateToken, (req, res) => {
    res.json({ isValid: true });
});


app.get('/city-pollution', (req, res) => {
    pollution_db.all('SELECT * FROM city_pollution', (err, rows) => {
        if (err) {
            return res.status(500).json({ error: 'Database error' });
        }
        res.json(rows);
    });
});
app.get('/profile', authenticateToken, (req, res) => {
    db.get('SELECT id, name, email FROM users WHERE id = ?', [req.user.id], (err, user) => {
        if (err) {
            return res.status(500).json({ error: 'Database error' });
        }
        if (!user) {
            return res.status(404).json({ error: 'User not found' });
        }
        res.json({
            id: user.id,
            name: user.name,
            email: user.email
        });
    });
});
function insertInitialData() {
    const initialData = [
        ['Mumbai', 'Maharashtra', 'India', 40.0, 60.0, 55.0, 15.0, 1.0, 50.0, '2024-08-13'],
        ['Delhi', 'Delhi', 'India', 120.0, 180.0, 100.0, 20.0, 2.0, 70.0, '2024-08-13'],
        ['Bangalore', 'Karnataka', 'India', 30.0, 45.0, 40.0, 8.0, 0.8, 55.0, '2024-08-13'],
        ['Kolkata', 'West Bengal', 'India', 60.0, 80.0, 70.0, 12.0, 1.2, 65.0, '2024-08-13'],
        ['Hyderabad', 'Telangana', 'India', 50.0, 70.0, 60.0, 18.0, 1.1, 60.0, '2024-08-13'],
        ['Chennai', 'Tamil Nadu', 'India', 45.0, 65.0, 50.0, 14.0, 1.0, 55.0, '2024-08-13']
    ];

    const stmt = pollution_db.prepare(`INSERT INTO city_pollution (name, state, country, pm2_5, pm10, no2, so2, co, o3, date) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`);

    initialData.forEach(row => {
        stmt.run(row, (err) => {
            if (err) {
                console.error('Error inserting data:', err);
            }
        });
    });

    stmt.finalize();
}


const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
