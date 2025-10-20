const express = require('express');
const Attendance = require('../models/Attendance');
const auth = require('../middleware/auth');
const router = express.Router();

router.post('/mark', auth, async (req, res) => {
  const { event_id } = req.body;
  const attendance = new Attendance({ user_id: req.user.id, event_id });
  await attendance.save();
  res.json({ message: 'Attendance marked' });
});

router.get('/history', auth, async (req, res) => {
  const history = await Attendance.find({ user_id: req.user.id }).populate('event_id');
  res.json(history);
});

router.get('/', auth, async (req, res) => {
  if (req.user.role !== 'admin') return res.status(403).json({ message: 'Access denied' });
  const attendance = await Attendance.find().populate('user_id event_id');
  res.json(attendance);
});

module.exports = router;