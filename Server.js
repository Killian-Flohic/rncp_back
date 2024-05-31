const express = require('express');
const bodyParser = require('body-parser');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const mysql = require('mysql2');
require('dotenv').config();
const qrcode = require('qrcode');
const speakeasy = require('speakeasy');

const app = express();
app.use(bodyParser.json());
app.use(cors());

// var test = speakeasy.generateSecret({name: 'rncp'});
// console.log(test);

// Database connection
const db = mysql.createConnection({
    host: 'localhost',
    port: 3306, // MAMP
    user: 'root',
    password: 'root',
    database: 'rncp_db'
});

db.connect((err) => {
    if (err) throw err;
    console.log('MySQL connected...');
});

// Register endpoint
app.post('/Register', (req, res) => {
    const { username, password, email } = req.body;
    const hashedPassword = bcrypt.hashSync(password, 8);

    db.query('INSERT INTO users (username, password, email) VALUES (?, ?, ?)', [username, hashedPassword, email], (err, result) => {
        if (err) return res.status(500).send('Error on the server.');
        res.status(200).send({ message: 'User registered successfully!' });
    });
});

// Login endpoint
app.post('/Login', (req, res) => {
    const { username, password } = req.body;

    db.query('SELECT * FROM users WHERE username = ?', [username], (err, results) => {
        if (err) return res.status(500).send('Error on the server.');
        if (results.length === 0) return res.status(404).send('No user found.');

        const user = results[0];
        const passwordIsValid = bcrypt.compareSync(password, user.password);
        
        if (!passwordIsValid) return res.status(401).send({ auth: false, token: null });

        const token = jwt.sign({ id: user.id }, process.env.SECRET, {
            expiresIn: 86400 // expires in 24 hours
        });

        res.status(200).send({ auth: true, token: token });
    });
});


// Middleware to verify token
const verifyToken = (req, res, next) => {
    const token = req.headers['x-access-token'];
    if (!token) return res.status(403).send({ auth: false, message: 'No token provided.' });

    jwt.verify(token, process.env.SECRET, (err, decoded) => {
        if (err) return res.status(500).send({ auth: false, message: 'Failed to authenticate token.' });
        req.userId = decoded.id;
        next();
    });
};

// Protected endpoint
app.get('/me', verifyToken, (req, res) => {
    db.query('SELECT * FROM users WHERE id = ?', [req.userId], (err, results) => {
        if (err) return res.status(500).send('There was a problem finding the user.');
        if (results.length === 0) return res.status(404).send('No user found.');

        res.status(200).send(results[0]);
    });
});


// Enable 2FA for a user
app.post('/Enable2FA', verifyToken, (req, res) => {
    const secret = speakeasy.generateSecret({name: 'rncp'});
    // console.log(secret);
    const url = speakeasy.otpauthURL({ secret: secret.base32, label: `rncp (${req.userId})`, algorithm: 'sha1' });
    // console.log(url);

    db.query('UPDATE users SET secret = ? WHERE id = ?', [secret.base32, req.userId], (err, result) => {

        if (err) return res.status(500).send('Error saving 2FA secret.');
        qrcode.toDataURL(url, (err, data_url) => {
            if (err) return res.status(500).send('Error generating QR code.');
            res.status(200).send({ qrCodeUrl: data_url, secret: secret.base32 });
        });
    });
});


app.post('/Verify2FA', verifyToken, (req, res) => {
    const { token } = req.body;

    db.query('SELECT secret FROM users WHERE id = ?', [req.userId], (err, results) => {
        if (err) return res.status(500).send('Error fetching 2FA secret.');
        if (results.length === 0) return res.status(404).send('No user found.');

        const verified = speakeasy.totp.verify({
            secret: results[0].secret,
            encoding: 'base32',
            token: token
        });

        if (!verified) return res.status(401).send('Invalid token.');

        res.status(200).send('2FA verified successfully.');
    });
});



app.listen(3001, () => {
    console.log('Server port 3001');
});


