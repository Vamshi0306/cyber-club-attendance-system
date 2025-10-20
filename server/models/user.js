const mongoose = require('mongoose');
const userSchema = new mongoose.Schema({
  name: { type: String, required: true },
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  branch: { type: String, enum: ['Cyber Security', 'AIML'], required: true },
  year: { type: Number, enum: [2, 3], required: true },
  profile_pic: { type: String, default: '' },
  role: { type: String, enum: ['student', 'admin'], default: 'student' },
  created_at: { type: Date, default: Date.now }
});
module.exports = mongoose.model('User', userSchema);