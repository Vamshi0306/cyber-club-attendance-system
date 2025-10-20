async function showPage(page) {
  if (page === 'landing') {
    // Embed landing content directly
    document.getElementById('content').innerHTML = `
      <div class="hero">
        <h1>Welcome to Cyber Club Attendance System</h1>
        <p>Manage your profile, mark attendance, and track events easily.</p>
        <button onclick="showPage('register')" class="btn btn-primary">Get Started</button>
      </div>
    `;
    updateNav(false);
    return;
  }
  try {
    const response = await fetch(`${page}.html`);
    if (!response.ok) throw new Error(`HTTP ${response.status}: ${response.statusText}`);
    const html = await response.text();
    document.getElementById('content').innerHTML = html;
    updateNav(page === 'profile' || page === 'attendance' || page === 'leaderboard');
    // ... rest of the function (loaders)
  } catch (error) {
    console.error('Error loading page:', error);
    alert(`Failed to load ${page}: ${error.message}. Check console for details.`);
  }
}

// Initial load
showPage('landing');

