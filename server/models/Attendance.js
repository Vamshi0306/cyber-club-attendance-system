const mongoose = require('mongoose');
const attendanceSchema = new mongoose.Schema({
  user_id: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  event_id: { type: mongoose.Schema.Types.ObjectId, ref: 'Event', required: true },
  status: { type: String, enum: ['Present', 'Absent'], default: 'Present' },
  marked_at: { type: Date, default: Date.now }
});
module.exports = mongoose.model('Attendance', attendanceSchema);