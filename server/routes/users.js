const express = require('express');
const User = require('../models/User');
const auth = require('../middleware/auth');
const multer = require('multer');
const router = express.Router();

const upload = multer({ dest: 'uploads/' });

router.get('/profile', auth, async (req, res) => {
  const user = await User.findById(req.user.id);
  res.json(user);
});

router.put('/profile', auth, upload.single('profile_pic'), async (req, res) => {
  const updates = req.body;
  if (req.file) updates.profile_pic = req.file.path;
  await User.findByIdAndUpdate(req.user.id, updates);
  res.json({ message: 'Profile updated' });
});

router.get('/', auth, async (req, res) => {
  if (req.user.role !== 'admin') return res.status(403).json({ message: 'Access denied' });
  const users = await User.find();
  res.json(users);
});

module.exports = router;