// import express from 'express';
// import mysql from 'mysql';
// import cors from 'cors';
// import bcrypt from 'bcrypt';
// import jwt from 'jsonwebtoken';
// import crypto from 'crypto';
// import session from 'express-session';
// import cookieParser from 'cookie-parser';
const express = require('express');
const mysql = require('mysql');
const cors = require('cors');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const session = require('express-session');
const cookieParser = require('cookie-parser');


const app = express();
const PORT = 3306
app.use(cors());
app.use(express.json());
app.use(cookieParser());
app.use(session({
    secret: 'jwt',
    resave: false,
    saveUninitialized: true,
    cookie: { secure: true },
})
);

const secretKey = crypto.randomBytes(32).toString('hex');
console.log('Generated Secret Key:', secretKey);

const db = mysql.createConnection({
    host: 'localhost',
    user: 'root',
    password: '',
    database: 'details_db'
})

app.get('/', (req, res) => {
    const sql = 'SELECT * FROM students';
    db.query(sql, (err, result) => {
        if (err) return res.json({ Message: 'Error Inside Server' });
        return res.json(result);
    })
})

app.post('/students', (req, res) => {
    const sql = 'INSERT INTO students (`rollno`,`name`,`course`,`address`,`contact`,`email`) VALUES (?)';
    const values = [
        req.body.rollno,
        req.body.name,
        req.body.course,
        req.body.address,
        req.body.contact,
        req.body.email
    ]
    db.query(sql, [values], (err, result) => {
        if (err) return res.json(err);
        return res.json(result);
    })
})

app.get('/read/:id', (req, res) => {
    const sql = 'SELECT * FROM students WHERE studentid = ?';
    const id = req.params.id;

    db.query(sql, [id], (err, result) => {
        if (err) return res.json({ Message: 'Error Inside Server' });
        return res.json(result);
    })
})

app.put('/update/:id', (req, res) => {
    const sql = 'UPDATE students SET `rollno`=?, `name`=?, `course`=?, `address`=?, `contact`=?, `email`=? WHERE studentid=?';
    const id = req.params.id;
    db.query(sql, [req.body.rollno, req.body.name, req.body.course, req.body.address, req.body.contact, req.body.email, id], (err, result) => {
        if (err) return res.json({ Message: 'Error From Server' });
        return res.json(result);
    })
})

app.delete('/delete/:id', (req, res) => {
    const sql = 'DELETE FROM students WHERE studentid=?';
    const id = req.params.id;
    db.query(sql, [id], (err, result) => {
        if (err) return res.json({ Message: 'Error From Server' });
        return res.json(result);
    })
})



// Second table code

app.post('/signup', (req, res) => {
    const { stdname, stdemail, stdcontact, password } = req.body;

    //checking for user's already existence
    db.query('SELECT * FROM registration WHERE stdemail=?', [stdemail], (err, results) => {
        if (err) {
            console.error(err);
            return res.json(500).send('Error on the server');
        }
        if (results.length > 0) {
            return res.status(409).send('User Already Exist');
        }
    })

    //If user doesn't exist
    const sql = 'INSERT INTO registration (`stdname`,`stdemail`,`stdcontact`,`password`) VALUES (?, ?, ?, ?)';
    const hashedPassword = bcrypt.hashSync(password, 10);
    console.log('Hashed Password:', hashedPassword);

    const values = [
        stdname,
        stdemail,
        stdcontact,
        hashedPassword
    ];
    db.query(sql, values, (error, result) => {
        if (error) {
            console.error(error)
            return res.status(500).send('Error on the Server');
        }
        
        return res.status(201).json({ message: 'Registration Successfull' })
    })
})


app.post('/login', (req, res) => {
    const { stdemail, password } = req.body;

    db.query('SELECT * FROM registration WHERE stdemail=?', [stdemail], (err, results) => {
        if (err) {
            console.error(err);
            return res.status(500).send('Error on the Server');
        }

        if (results.length === 0) {
            return res.status(401).send('User Not Found');
        }

        const user = results[0];
        console.log('Hashed Password from Database:', user.password);
        if (bcrypt.compareSync(password, user.password)) {

            console.log('Password Matched')
            const token = jwt.sign({ userId: user.studentid, role: 'user' }, secretKey, { expiresIn: '10h' });
            req.session.jwt = token;
            res.cookie('jwt', token, { httpOnly: true, secure: false });

            return res.status(200).json({ Message: 'Login Successful', token });
        } else {
            console.log('Password Mismatch')
            return res.status(401).json({ message: 'Invalid Credentials' });
        }
    })
})

app.listen(PORT, () => {
    console.log('Listening....');
})
