const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const User = require('../models/User');
const nodemailer = require('nodemailer');
const router = express.Router();

const transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: { user: process.env.EMAIL_USER, pass: process.env.EMAIL_PASS }
});

router.post('/register', async (req, res) => {
  const { name, email, password, branch, year } = req.body;
  const hashedPassword = await bcrypt.hash(password, 10);
  const user = new User({ name, email, password: hashedPassword, branch, year });
  await user.save();
  transporter.sendMail({ from: process.env.EMAIL_USER, to: email, subject: 'Registration Successful', text: 'Welcome!' });
  res.status(201).json({ message: 'User registered' });
});

router.post('/login', async (req, res) => {
  const user = await User.findOne({ email: req.body.email });
  if (user && await bcrypt.compare(req.body.password, user.password)) {
    const token = jwt.sign({ id: user._id, role: user.role }, process.env.JWT_SECRET, { expiresIn: '1h' });
    res.json({ token, user });
  } else {
    res.status(401).json({ message: 'Invalid credentials' });
  }
});


module.exports = router;
