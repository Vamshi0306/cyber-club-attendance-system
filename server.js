const express = require('express');
const fs = require('fs');
const path = require('path');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const dotenv = require('dotenv');
dotenv.config();

const app = express();
app.use(cors());
app.use(express.json());

const dataPath = path.join(__dirname, 'data.json');

// Helper to read/write JSON
const readData = () => JSON.parse(fs.readFileSync(dataPath, 'utf8'));
const writeData = (data) => fs.writeFileSync(dataPath, JSON.stringify(data, null, 2));

// Auth routes
app.post('/api/auth/register', async (req, res) => {
  const { name, email, password, branch, year } = req.body;
  const data = readData();
  if (data.users.find(u => u.email === email)) return res.status(400).json({ message: 'Email exists' });
  const hashedPassword = await bcrypt.hash(password, 10);
  const user = { id: Date.now().toString(), name, email, password: hashedPassword, branch, year, role: 'student' };
  data.users.push(user);
  writeData(data);
  res.status(201).json({ message: 'User registered' });
});

app.post('/api/auth/login', async (req, res) => {
  const { email, password } = req.body;
  const data = readData();
  const user = data.users.find(u => u.email === email);
  if (user && await bcrypt.compare(password, user.password)) {
    const token = jwt.sign({ id: user.id, role: user.role }, process.env.JWT_SECRET || 'testsecret', { expiresIn: '1h' });
    res.json({ token, user });
  } else {
    res.status(401).json({ message: 'Invalid credentials' });
  }
});

// Middleware for auth
const auth = (req, res, next) => {
  const token = req.header('Authorization')?.replace('Bearer ', '');
  if (!token) return res.status(401).json({ message: 'No token' });
  try {
    req.user = jwt.verify(token, process.env.JWT_SECRET || 'testsecret');
    next();
  } catch (e) {
    res.status(401).json({ message: 'Invalid token' });
  }
};

// User routes
app.get('/api/users/profile', auth, (req, res) => {
  const data = readData();
  const user = data.users.find(u => u.id === req.user.id);
  res.json(user);
});

app.put('/api/users/profile', auth, (req, res) => {
  const data = readData();
  const userIndex = data.users.findIndex(u => u.id === req.user.id);
  if (userIndex !== -1) {
    data.users[userIndex] = { ...data.users[userIndex], ...req.body };
    writeData(data);
    res.json({ message: 'Profile updated' });
  }
});

// Event routes
app.get('/api/events', (req, res) => {
  const data = readData();
  res.json(data.events);
});

app.post('/api/events', auth, (req, res) => {
  if (req.user.role !== 'admin') return res.status(403).json({ message: 'Access denied' });
  const data = readData();
  const event = { id: Date.now().toString(), ...req.body };
  data.events.push(event);
  writeData(data);
  res.status(201).json(event);
});

// Attendance routes
app.post('/api/attendance/mark', auth, (req, res) => {
  const { event_id } = req.body;
  const data = readData();
  const attendance = { id: Date.now().toString(), user_id: req.user.id, event_id, status: 'Present' };
  data.attendance.push(attendance);
  writeData(data);
  res.json({ message: 'Attendance marked' });
});

app.get('/api/attendance/history', auth, (req, res) => {
  const data = readData();
  const history = data.attendance.filter(a => a.user_id === req.user.id).map(a => ({
    ...a,
    event_id: data.events.find(e => e.id === a.event_id)
  }));
  res.json(history);
});

app.listen(5000, () => console.log('Server running on port 5000 (JSON mode)'));
