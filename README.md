# 🛡️ Cyber Club Attendance & Management System

A full-stack web application built with Python and Flask for managing club members, events, and attendance. This project features a secure "Admin Approval" system for new members, a student dashboard with attendance tracking, and an admin-only control panel for managing all aspects of the club.

![App Screenshot](https://i.imgur.com/your-screenshot-url.png)
*(Suggestion: Take a screenshot of your app, upload it to a site like [Imgur](https://imgur.com/), and paste the link here.)*

---

## 🚀 Core Features

* **Secure Admin Approval:** New users can register, but their accounts are "pending" until an admin approves them.
* **Student Dashboard:** Students see a list of upcoming events and can mark their attendance with a single click.
* **Attendance Tracking:** The dashboard shows a bar graph of the student's personal attendance (attended vs. missed).
* **Admin Control Panel:** A dashboard for the admin to:
    * Approve or Deny pending members.
    * View all approved students.
    * Create, manage, and delete events.
    * View detailed reports for each event with a pie chart and lists of attendees/absentees.
* **Resource Hub:** A page where admins can post links and resources for all club members to see.
* **Professional UI:** Built with a custom "Cyborg" theme, creative buttons, and a transparent logo background.

---

## 🛠️ Tech Stack

* **Backend:** Python (Flask)
* **Frontend:** HTML, CSS, Bootstrap 5 (Cyborg Theme)
* **Database:** SQLite
* **Profile Pictures:** `Pillow` for image processing.
* **Charts:** `Chart.js` for data visualization.

---

## 🔧 How to Run This Project

1.  **Clone the repository:**
    ```bash
    git clone [https://github.com/vamshi0306/cyber-club-attendance-system.git](https://github.com/vamshi0306/cyber-club-attendance-system.git)
    cd cyber-club-attendance-system
    ```

2.  **Install the requirements:**
    *(If in Termux, you may need to install `build-essential`, `libjpeg-turbo`, `libpng`, and `rust` first via `pkg install`)*
    ```bash
    pip install -r requirements.txt
    ```

3.  **Initialize the database:**
    This will create your database and your default admin account.
    ```bash
    flask init-db
    ```

4.  **Run the application:**
    ```bash
    flask run
    ```

5.  Open your browser and go to `http://127.0.0.1:5000`

---

### 🔑 Admin Credentials (for first login)

* **Email:** `admin_cyberclub@gmail.com`
* **Password:** `password`
