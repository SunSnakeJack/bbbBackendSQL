var express = require('express')
var cors = require('cors')
var app = express()
var bodyParser = require('body-parser')
var jsonParser = bodyParser.json()
const bcrypt = require('bcrypt');
const saltRounds = 10;
var jwt = require('jsonwebtoken');
const secret = 'backend-Test-2024'
app.use(express.json())
app.use(bodyParser.json());

app.use(cors())

const mysql = require('mysql2');

const connection = mysql.createConnection({
    host: 'localhost',
    user: 'root',
    database: 'mydb'
})

function authenticateToken(req, res, next) {
    const authHeader = req.headers['authorization' ];
    const token = authHeader && authHeader.split(' ')[1];

    if (token == null) return res.status(401).json({ status: 'forbidden', message: 'No token provided.'  });

    jwt.verify(token, secret, (err, user) => {
        if (err) return res.status(403).json({ status: 'forbidden', message: 'Failed to authenticate token.' });
        console.log('Decoded token',user)
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
    connection.execute(
        'SELECT id, fname, lname, email, image FROM users WHERE email = ?',
        [req.user.email],
        function (err, users, fields) {
            if (err) { res.json({ status: 'error', message: err }); return }
            if (users.length == 0) { res.json({ status: 'error', message: 'user not found' }); return }

            const user = {
                id: users[0].id,
                fname: users[0].fname,
                lname: users[0].lname,
                email: users[0].email,
                image: users[0].image ? Buffer.from(users[0].image).toString('base64') : null

            };

            res.json({ status: 'ok', user });
        }
    );
});

app.get('/findAllBooking', (req, res) => {
    const sql = `
        SELECT 
            users.fname, 
            rooms.roomName
        FROM 
            bookings
        JOIN 
            users ON bookings.userId = users.id
        JOIN 
            rooms ON bookings.roomId = rooms.roomId
        ORDER BY 
            users.fname;
    `;

    connection.query(sql, (err, results) => {
        if (err) throw err;
        res.json(results);
    });
});

app.get('/bookingDetail', authenticateToken, (req, res) => {

    // if (!req.user || !req.user.id) {
    //     return res.status(400).json({ status: 'error', message: 'User ID not found in token' });
    // }
    connection.execute(`
            SELECT 
                users.fname AS Username, 
                rooms.roomId AS NumberOfRooms,
                rooms.roomName,
                rooms.roomType,
                rooms.roomPrice,
                rooms.roomArea,
                bookings.checkIn,
                bookings.checkOut,
                rooms.roomImage
            FROM 
                bookings
            JOIN 
                users ON bookings.userId = users.id
            JOIN 
                rooms ON bookings.roomId = rooms.roomId
            WHERE 
                users.email = ?`,
                [req.user.email],
            function (err, results, fields) {
                if (err) { res.json({ status: 'error', message: err }); return }
                if (results.length == 0) { res.json({ status: 'error', message: 'user not found' }); return }

                const booking = {
                    Username: results[0].Username,
                    NumberOfRooms: results[0].NumberOfRooms,
                    roomName: results[0].roomName,
                    roomType: results[0].roomType,
                    roomPrice: results[0].roomPrice,
                    roomArea: results[0].roomArea,
                    checkIn: results[0].checkIn,
                    checkOut: results[0].checkOut,
                    roomImage: results[0].roomImage ? Buffer.from(results[0].roomImage).toString('base64') : null
                };

                res.json({ status: 'ok', booking})
            }
         )
})

app.post('/booking', authenticateToken ,(req, res) => {
    const { roomId, checkIn, checkOut } = req.body;

    const sql = 'INSERT INTO bookings (userId, roomId, checkIn, checkOut) VALUES (?, ?, ?, ?)';
    connection.query(sql, [userId, roomId, checkIn, checkOut], (err, result) => {
        if (!userId || !roomId || !checkIn || !checkOut) {
            return res.status(400).json({ error: 'Missing required fields' });
        }
        if (err) {
            console.error('Error inserting data:', err);
            res.status(500).json({ error: 'Failed to book room' });
        } else {
            res.status(200).json({ message: 'Room booked successfully' });
        }
    });
});

app.listen(3333, function () {
    console.log('CORS-enabled web server listening on port 3333')
})

// app.get('/userDetail', (req, res) => {
//     const token = req.headers.authorization?.split(' ')[1];
//     if (!token) {
//         return res.status(403).send('No token provided');
//     }

//     // ตรวจสอบและถอดรหัส token
//     jwt.verify(token, secret, (err, decoded) => {
//         if (err) {
//             return res.status(403).send('Failed to authenticate token');
//         }

//         const userId = decoded.id;
//         console.log('Decoded userId:', userId);

//         const sql = `
//             SELECT
//                 users.fname AS Username,
//                 rooms.roomId AS NumberOfRooms,
//                 rooms.roomName,
//                 rooms.roomType,
//                 rooms.roomPrice,
//                 rooms.roomArea,
//                 bookings.checkIn,
//                 bookings.checkOut,
//                 rooms.roomImage
//             FROM
//                 bookings
//             JOIN
//                 users ON bookings.userId = users.id
//             JOIN
//                 rooms ON bookings.roomId = rooms.roomId
//             WHERE
//                 users.id = ?
//         `;

//         connection.query(sql, [userId], (err, results) => {
//             if (err) {
//                 console.error(err);
//                 res.status(500).send('Server Error');
//                 return;
//             }
//             res.json(results);  // ส่งผลลัพธ์กลับในรูปแบบ JSON
//         });
//     });  // ปิดการเรียกใช้ jwt.verify
// }); 