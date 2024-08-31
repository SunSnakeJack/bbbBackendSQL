var express = require('express')
var cors = require('cors')
var app = express()
var bodyParser = require('body-parser')
var jsonParser = bodyParser.json()
const bcrypt = require('bcrypt');
const saltRounds = 10;
var jwt = require('jsonwebtoken');
const secret = 'backend-Test-2024'

app.use(cors())

const mysql = require('mysql2');

const connection = mysql.createConnection({
    host: 'localhost',
    user: 'root',
    database: 'mydb'
})

function authenticateToken(req, res, next) {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (token == null) return res.status(401).json({ status: 'forbidden', message: 'No token provided.' });

    jwt.verify(token, secret, (err, user) => {
        if (err) return res.status(403).json({ status: 'forbidden', message: 'Failed to authenticate token.' });
        req.user = user;
        next();
    });
}

app.post('/register', jsonParser, function (req, res, next) {
    bcrypt.hash(req.body.password, saltRounds, function (err, hash) {
        connection.execute(
            'INSERT INTO users (email, password , fname , lname) VALUES (?,?,?,?)',
            [req.body.email, hash, req.body.fname, req.body.lname],
            function (err, results, fields) {
                if (err) {
                    res.json({ status: 'error', message: err })
                    return
                }
                res.json({ status: 'ok' })
            }
        )
    });
})

app.post('/login', jsonParser, function (req, res, next) {
    connection.execute(
        'SELECT * FROM users WHERE email=? ',
        [req.body.email],
        function (err, users, fields) {
            if (err) { res.json({ status: 'error', message: err }); return }
            if (users.length == 0) { res.json({ status: 'error', message: 'no user found' }); return }
            bcrypt.compare(req.body.password, users[0].password, function (err, isLogin) {
                if (isLogin) {
                    const accessToken = jwt.sign({ email: users[0].email }, secret, { expiresIn: '1h' });
                    res.json({ status: 'ok', message: ' login success', accessToken: accessToken })
                } else {
                    res.json({ status: 'error', message: ' login failed' })
                }
            });
        }
    )
})
app.post('/authen', jsonParser, function (req, res, next) {
    try {
        var token = req.headers.authorization.split(' ')[1]
        var decoded = jwt.verify(token, secret);
        res.json({ status: 'ok', decoded });
    } catch (err) {
        res.json({ status: 'error', message: err.message });
    }
})


app.get('/profile', authenticateToken, (req, res) => {
    const user = {
        id: req.user.id,
        fname: req.user.fname,
        lname: req.user.lname,
        email: req.user.email,
    };

    res.json({ status: 'ok', user });
});

app.listen(3333, function () {
    console.log('CORS-enabled web server listening on port 3333')
})