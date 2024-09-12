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
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];


    if (token == null) return res.status(401).json({ status: 'forbidden', message: 'No token provided.' });

    jwt.verify(token, secret, (err, user) => {
        if (err) return res.status(403).json({ status: 'forbidden', message: 'Please login' });
        console.log('Decoded token', user)



        req.user = { userId: user.userId, email: user.email };
        next();
    });

}

app.post('/register', jsonParser, function (req, res, next) {
    bcrypt.hash(req.body.password, saltRounds, function (err, hash) {
        connection.execute(
            'INSERT INTO users (email, password , fname , lname , phoneNumber ) VALUES (?,?,?,?,?)',
            [req.body.email, hash, req.body.fname, req.body.lname, req.body.phoneNumber],
            function (err, results, fields) {
                if (err) {
                    res.json({ status: 'error', message: err })
                    return
                }
                res.json({ status: 'ok', message: 'Register successfully' })
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
                    const accessToken = jwt.sign({ userId: users[0].userId, email: users[0].email }, secret, { expiresIn: '1h' });
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
        'SELECT userId, fname, lname, email, image FROM users WHERE email = ?',
        [req.user.email],
        function (err, users, fields) {
            if (err) { res.json({ status: 'error', message: err }); return }
            if (users.length == 0) { res.json({ status: 'error', message: 'user not found' }); return }

            const user = {
                id: users[0].userId,
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
            users ON bookings.userId = users.userId
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

    if (!req.user || !req.user.email) {
        return res.status(400).json({ status: 'error', message: 'User ID not found in token' });
    }
    connection.execute(`
            SELECT  
                bookings.bookingNumber,
                rooms.roomId AS NumberOfRooms,
                rooms.roomName,
                rooms.roomType,
                bookings.checkIn,
                bookings.checkOut,
                bookings.payment
            FROM 
                bookings
            JOIN 
                users ON bookings.userId = users.userId
            JOIN 
                rooms ON bookings.roomId = rooms.roomId
            WHERE 
                users.email = ?`,
        [req.user.email],
        function (err, results, fields) {
            if (err) { res.json({ status: 'error', message: err }); return }
            if (results.length == 0) { res.json({ status: 'error', message: 'user not found' }); return }

            const booking = results.map(result => ({
                bookingNumber: result.bookingNumber,
                NumberOfRooms: result.NumberOfRooms,
                roomName: result.roomName,
                roomType: result.roomType,
                checkIn: result.checkIn,
                checkOut: result.checkOut,
                payment: result.payment
            }));

            res.json({ status: 'ok', booking });
        }
    )
})

const crypto = require('crypto');

function generateRandomBookingNumber(length) {
    const charset = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
    const fixedPrefix = 'BBB';  // กำหนดค่าตัวอักษรที่ต้องการให้เป็น 3 ตัวหน้า
    let result = fixedPrefix;

    // ตรวจสอบความยาวที่เหลือ
    const remainingLength = length - fixedPrefix.length;

    // สร้างตัวอักษรสุ่มสำหรับส่วนที่เหลือ
    for (let i = 0; i < remainingLength; i++) {
        const randomIndex = Math.floor(Math.random() * charset.length);
        result += charset[randomIndex];
    }

    return result;
}
// ฟังก์ชันลบ booking ที่ยังมีสถานะเป็น pending และผ่านเวลาเกิน 10 นาที
function removePendingBooking(userId, roomId, callback) {
    const tenMinutesAgo = new Date(Date.now() - 1 * 60 * 1000);  // เวลาปัจจุบันลบด้วย 10 นาที
    const sql = 'DELETE FROM bookings WHERE userId = ? AND roomId = ? AND bookingStatus = "pending" AND createdAt < ?';
    
    connection.query(sql, [userId, roomId, tenMinutesAgo], (err, result) => {
        if (err) {
            console.error('Error deleting pending booking:', err);
            return callback(err);
        }
        if (result.affectedRows > 0) {
            console.log(`Pending booking for user ${userId} in room ${roomId} has been deleted due to exceeding 10 minutes.`);
        }
        callback(null);  // ส่ง callback กลับไปเพื่อบอกว่าเสร็จสิ้น
    });
}
app.post('/booking', authenticateToken, (req, res) => {
    const { roomId, checkIn, checkOut, adultsCount, childrenCount } = req.body;
    const userId = req.user.userId;
    const bookingNumber = generateRandomBookingNumber(8);

    if (!roomId || !checkIn || !checkOut || !adultsCount || !childrenCount) {
        return res.status(400).json({ error: 'Missing required fields' });
    }

    const checkInDate = new Date(checkIn);
    const checkOutDate = new Date(checkOut);

    if (checkOutDate < checkInDate) {
        return res.status(400).json({ error: 'Check-out date cannot be before check-in date' });
    }

    const isSameDay = checkInDate.toDateString() === checkOutDate.toDateString();
    
    if (isSameDay) {
        return res.status(400).json({ error: 'Check-out date cannot be the same as check-in date' });
    }

    const duration = Math.ceil((checkOutDate - checkInDate) / (1000 * 60 * 60 * 24));

    // ตรวจสอบว่ามีการจองห้องในช่วงวันที่นี้หรือไม่
    const checkAvailabilitySql = `
        SELECT * FROM bookings 
        WHERE roomId = ? 
        AND bookingStatus != "cancelled"
        AND ((checkIn <= ? AND checkOut >= ?) OR (checkIn <= ? AND checkOut >= ?))
    `;
    
    connection.query(checkAvailabilitySql, [roomId, checkOutDate, checkInDate, checkInDate, checkOutDate], (err, result) => {
        if (err) {
            console.error('Error checking room availability:', err);
            return res.status(500).json({ error: 'Failed to check room availability' });
        }

        // ถ้ามีการจองในช่วงเวลาที่กำหนด จะแจ้งว่าห้องเต็ม
        if (result.length > 0) {
            return res.status(400).json({ error: 'Room is fully booked for the selected dates' });
        }

        // ดึง roomPrice จากตาราง rooms
        const priceSql = 'SELECT roomPrice FROM rooms WHERE roomId = ?';
        connection.query(priceSql, [roomId], (err, result) => {
            if (err) {
                console.error('Error fetching room price:', err);
                return res.status(500).json({ error: 'Failed to fetch room price' });
            }

            if (result.length === 0) {
                return res.status(404).json({ error: 'Room not found' });
            }

            const roomPrice = result[0].roomPrice;
            const cost = duration * roomPrice;

            // แทรกการจองใหม่
            const bookingSql = 'INSERT INTO bookings (bookingNumber, userId, roomId, checkIn, checkOut, adultsCount, childrenCount, duration, cost, bookingStatus) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, "pending")';
            connection.query(bookingSql, [bookingNumber, userId, roomId, checkIn, checkOut, adultsCount, childrenCount, duration, cost], (err, result) => {
                if (err) {
                    console.error('Error inserting booking:', err);
                    return res.status(500).json({ error: 'Failed to book room' });
                }

                res.status(200).json({ status: 'ok', message: 'Room booked successfully', bookingNumber, cost });

                // ตั้งเวลา 10 นาทีเพื่อลบ booking ถ้าสถานะยังเป็น pending
                setTimeout(() => {
                    const deleteSql = 'DELETE FROM bookings WHERE bookingNumber = ? AND bookingStatus = "pending"';
                    connection.query(deleteSql, [bookingNumber], (err, result) => {
                        if (err) {
                            console.error('Error deleting pending booking:', err);
                        } else if (result.affectedRows > 0) {
                            console.log(`Booking ${bookingNumber} has been deleted due to pending status for more than 10 minutes.`);
                        }
                    });
                }, 10 * 60 * 1000);  // ลบหลังจาก 10 นาที (10 * 60 * 1000 milliseconds)
            });
        });
    });
});








// const dns = require('dns');

// function checkEmailExists(email, callback) {
//     const domain = email.split('@')[1];
//     dns.resolveMx(domain, (err, addresses) => {
//         if (err || addresses.length === 0) {
//             callback(false);
//         } else {
//             callback(true);
//         }
//     });
// }
// app.post('/checkDns', jsonParser, (req, res) => {
//     const email = req.body.email;
//     if (!email) {
//         return res.status(400).json({ status: 'error', message: 'Email parameter is required.' });
//     }
//     checkEmailExists(email, (exists) => {
//         if (exists) {
//             res.json({ exists: true });
//         } else {
//             res.json({ exists: false });
//         }
//     });
// });

app.post('/checkEmail', jsonParser, (req, res) => {
    const email = req.body.email;  // ใช้ req.body สำหรับ POST requests

    if (!email) {
        return res.status(400).json({ status: 'error', message: 'Email parameter is required.' });
    }

    const sql = 'SELECT * FROM users WHERE email = ?';
    connection.query(sql, [email], (err, results) => {
        if (err) {
            console.error('Database query error:', err);
            return res.status(500).json({ status: 'error', message: 'Database query failed.' });
        }

        if (results.length > 0) {
            return res.json({ exists: true });  // If email is found
        } else {
            return res.json({ exists: false });  // If email is not found
        }
    });
});


app.listen(3333, function () {
    console.log('CORS-enabled web server listening on port 3333')
})

