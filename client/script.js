let token = localStorage.getItem('token');
let currentUser = null;

async function showPage(page) {
  try {
    const response = await fetch(`${page}.html`);
    if (!response.ok) throw new Error(`HTTP ${response.status}: ${response.statusText}`);
    const html = await response.text();
    document.getElementById('content').innerHTML = html;
    updateNav(page === 'profile' || page === 'attendance' || page === 'leaderboard');
    if (page === 'register') loadRegister();
    if (page === 'login') loadLogin();
    if (page === 'profile') loadProfile();
    if (page === 'attendance') loadAttendance();
    if (page === 'leaderboard') loadLeaderboard();
  } catch (error) {
    console.error('Error loading page:', error);
    alert(`Failed to load ${page}: ${error.message}. Check console for details.`);
  }
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

async function apiCall(endpoint, method = 'GET', body = null) {
  try {
    const headers = { 'Content-Type': 'application/json' };
    if (token) headers['Authorization'] = `Bearer ${token}`;
    const response = await fetch(`http://localhost:5000/api/${endpoint}`, {
      method, headers, body: body ? JSON.stringify(body) : null
    });
    if (!response.ok) throw new Error(`HTTP ${response.status}: ${response.statusText}`);
    return await response.json();
  } catch (error) {
    console.error('API error:', error);
    alert(`API call failed: ${error.message}`);
    throw error;
  }
}

// Page loaders (unchanged, but now with error handling)
function loadRegister() {
  document.getElementById('register-form').addEventListener('submit', async (e) => {
    e.preventDefault();
    const formData = new FormData(e.target);
    const data = Object.fromEntries(formData);
    try {
      await apiCall('auth/register', 'POST', data);
      alert('Registered!');
      showPage('login');
    } catch (error) {
      alert('Registration failed: ' + error.message);
    }
  });
}

function loadLogin() {
  document.getElementById('login-form').addEventListener('submit', async (e) => {
    e.preventDefault();
    const formData = new FormData(e.target);
    const data = Object.fromEntries(formData);
    try {
      const res = await apiCall('auth/login', 'POST', data);
      if (res.token) {
        token = res.token;
        localStorage.setItem('token', token);
        currentUser = res.user;
        showPage('profile');
      } else {
        alert('Invalid credentials');
      }
    } catch (error) {
      alert('Login failed: ' + error.message);
    }
  });
}

async function loadProfile() {
  try {
    const user = await apiCall('users/profile');
    document.getElementById('profile-info').innerHTML = `
      <p>Name: ${user.name}</p>
      <p>Email: ${user.email}</p>
      <p>Branch: ${user.branch}</p>
      <p>Year: ${user.year}</p>
    `;
    document.getElementById('update-form').addEventListener('submit', async (e) => {
      e.preventDefault();
      const formData = new FormData(e.target);
      await apiCall('users/profile', 'PUT', Object.fromEntries(formData));
      alert('Profile updated');
      loadProfile();
    });
  } catch (error) {
    alert('Failed to load profile: ' + error.message);
  }
}

async function loadAttendance() {
  try {
    const events = await apiCall('events');
    const history = await apiCall('attendance/history');
    document.getElementById('events-list').innerHTML = events.map(e => `
      <li>${e.title} - ${e.date} <button onclick="markAttendance('${e._id}')">Mark</button></li>
    `).join('');
    document.getElementById('history-list').innerHTML = history.map(h => `
      <li>${h.event_id.title} - ${h.status}</li>
    `).join('');
  } catch (error) {
    alert('Failed to load attendance: ' + error.message);
  }
}

async function markAttendance(eventId) {
  try {
    await apiCall('attendance/mark', 'POST', { event_id: eventId });
    alert('Attendance marked');
    loadAttendance();
  } catch (error) {
    alert('Failed to mark attendance: ' + error.message);
  }
}

async function loadLeaderboard() {
  try {
    const users = await apiCall('users');
    document.getElementById('leaderboard-list').innerHTML = users.map(u => `<li>${u.name} - Attendances: 0</li>`).join('');
  } catch (error) {
    alert('Failed to load leaderboard: ' + error.message);
  }
}

// Initial load
showPage('landing');
