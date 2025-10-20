let token = localStorage.getItem('token');
let currentUser = null;

function showPage(page) {
  fetch(`${page}.html`)
    .then(response => response.text())
    .then(html => {
      document.getElementById('content').innerHTML = html;
      if (page === 'profile' || page === 'attendance' || page === 'leaderboard') {
        if (!token) { alert('Please login first'); showPage('login'); return; }
        updateNav(true);
      } else {
        updateNav(false);
      }
      // Load page-specific JS if needed
      if (page === 'register') loadRegister();
      if (page === 'login') loadLogin();
      if (page === 'profile') loadProfile();
      if (page === 'attendance') loadAttendance();
      if (page === 'leaderboard') loadLeaderboard();
    });
}

function updateNav(loggedIn) {
  document.getElementById('profile-btn').style.display = loggedIn ? 'inline' : 'none';
  document.getElementById('attendance-btn').style.display = loggedIn ? 'inline' : 'none';
  document.getElementById('leaderboard-btn').style.display = loggedIn ? 'inline' : 'none';
  document.getElementById('logout-btn').style.display = loggedIn ? 'inline' : 'none';
}

function logout() {
  localStorage.removeItem('token');
  token = null;
  showPage('landing');
}

// API helpers
async function apiCall(endpoint, method = 'GET', body = null) {
  const headers = { 'Content-Type': 'application/json' };
  if (token) headers['Authorization'] = `Bearer ${token}`;
  const res = await fetch(`http://localhost:5000/api/${endpoint}`, {
    method, headers, body: body ? JSON.stringify(body) : null
  });
  return res.json();
}

// Page loaders
function loadRegister() {
  document.getElementById('register-form').addEventListener('submit', async (e) => {
    e.preventDefault();
    const formData = new FormData(e.target);
    const data = Object.fromEntries(formData);
    await apiCall('auth/register', 'POST', data);
    alert('Registered! Please login.');
    showPage('login');
  });
}

function loadLogin() {
  document.getElementById('login-form').addEventListener('submit', async (e) => {
    e.preventDefault();
    const formData = new FormData(e.target);
    const data = Object.fromEntries(formData);
    const res = await apiCall('auth/login', 'POST', data);
    if (res.token) {
      token = res.token;
      localStorage.setItem('token', token);
      currentUser = res.user;
      showPage('profile');
    } else {
      alert('Invalid credentials');
    }
  });
}

async function loadProfile() {
  const user = await apiCall('users/profile');
  document.getElementById('profile-info').innerHTML = `
    <p>Name: ${user.name}</p>
    <p>Email: ${user.email}</p>
    <p>Branch: ${user.branch}</p>
    <p>Year: ${user.year}</p>
    <img src="${user.profile_pic || 'default.jpg'}" alt="Profile Pic" width="100">
  `;
  document.getElementById('update-form').addEventListener('submit', async (e) => {
    e.preventDefault();
    const formData = new FormData(e.target);
    await apiCall('users/profile', 'PUT', Object.fromEntries(formData));
    alert('Profile updated');
    loadProfile();
  });
}

async function loadAttendance() {
  const events = await apiCall('events');
  const history = await apiCall('attendance/history');
  document.getElementById('events-list').innerHTML = events.map(e => `
    <li>${e.title} - ${e.date} <button onclick="markAttendance('${e._id}')">Mark</button></li>
  `).join('');
  document.getElementById('history-list').innerHTML = history.map(h => `
    <li>${h.event_id.title} - ${h.status}</li>
  `).join('');
}

async function markAttendance(eventId) {
  await apiCall('attendance/mark', 'POST', { event_id: eventId });
  alert('Attendance marked');
  loadAttendance();
}

async function loadLeaderboard() {
  // Simplified: Fetch users and sort by attendance count (implement aggregation in backend if needed)
  const users = await apiCall('users');
  document.getElementById('leaderboard-list').innerHTML = users.map(u => `<li>${u.name} - Attendances: 0</li>`).join(''); // Placeholder
}

// Initial load
showPage('landing');