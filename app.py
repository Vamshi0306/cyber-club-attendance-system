import os
from flask import Flask, render_template, request, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_login import LoginManager, UserMixin, login_user, logout_user, current_user, login_required
from datetime import datetime

# --- APP & DATABASE CONFIGURATION ---

app = Flask(__name__)
# This secret key is for session management (keeping users logged in)
app.config['SECRET_KEY'] = 'a_very_secret_key_change_this'
# Set the database location
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///site.db'
# Folder to store uploaded profile pictures
app.config['UPLOAD_FOLDER'] = 'static/profile_pics'
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
# If a user tries to access a page they need to be logged in for, redirect them to the login page
login_manager.login_view = 'login'

# This function is required by Flask-Login to load a user from the database
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# --- DATABASE MODELS (TABLES) ---

# The UserMixin is required for Flask-Login to work
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(60), nullable=False) # Hashed password
    branch = db.Column(db.String(50), nullable=False)
    year = db.Column(db.Integer, nullable=False)
    profile_pic = db.Column(db.String(20), nullable=False, default='default.jpg')
    role = db.Column(db.String(10), nullable=False, default='student')
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    # Relationship to Attendance records
    attendance = db.relationship('Attendance', backref='attendee', lazy=True)

class Event(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    date = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    description = db.Column(db.Text, nullable=False)
    is_active = db.Column(db.Boolean, default=False) # To mark which event is current
    # Relationship to Attendance records
    attendance = db.relationship('Attendance', backref='event', lazy=True)

class Attendance(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    event_id = db.Column(db.Integer, db.ForeignKey('event.id'), nullable=False)
    marked_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)

# --- ROUTES (THE DIFFERENT WEB PAGES) ---

# Home Page
@app.route("/")
def home():
    # Find the currently active event to display
    active_event = Event.query.filter_by(is_active=True).first()
    return render_template('index.html', event=active_event)

# Registration Page
@app.route("/register", methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        # Get data from the form
        name = request.form.get('name')
        email = request.form.get('email')
        password = request.form.get('password')
        branch = request.form.get('branch')
        year = request.form.get('year')

        # Check if email already exists
        if User.query.filter_by(email=email).first():
            flash('Email already exists. Please log in.', 'danger')
            return redirect(url_for('login'))

        # Hash the password for security
        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
        # Create a new user object
        user = User(name=name, email=email, password=hashed_password, branch=branch, year=year)
        # Add to database
        db.session.add(user)
        db.session.commit()
        flash('Your account has been created! You can now log in.', 'success')
        return redirect(url_for('login'))
    return render_template('register.html')

# Login Page
@app.route("/login", methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        user = User.query.filter_by(email=email).first()
        # Check if user exists and password is correct
        if user and bcrypt.check_password_hash(user.password, password):
            login_user(user, remember=True) # Log the user in
            flash('Login successful!', 'success')
            return redirect(url_for('profile'))
        else:
            flash('Login unsuccessful. Please check email and password.', 'danger')
    return render_template('login.html')

# Logout
@app.route("/logout")
def logout():
    logout_user() # Log the user out
    return redirect(url_for('home'))

# Profile Page (requires user to be logged in)
@app.route("/profile", methods=['GET', 'POST'])
@login_required
def profile():
    if request.method == 'POST':
        # Update user details
        current_user.name = request.form.get('name')
        current_user.branch = request.form.get('branch')
        current_user.year = request.form.get('year')
        db.session.commit()
        flash('Your profile has been updated!', 'success')
        return redirect(url_for('profile'))
    return render_template('profile.html', user=current_user)

# Attendance Marking Page
@app.route("/mark_attendance")
@login_required
def mark_attendance():
    active_event = Event.query.filter_by(is_active=True).first()
    if not active_event:
        flash('No active session available to mark attendance.', 'warning')
        return redirect(url_for('home'))

    # Check if attendance is already marked for this event
    already_marked = Attendance.query.filter_by(user_id=current_user.id, event_id=active_event.id).first()
    if already_marked:
        flash('You have already marked attendance for this session.', 'info')
    else:
        # Mark attendance
        attendance = Attendance(user_id=current_user.id, event_id=active_event.id)
        db.session.add(attendance)
        db.session.commit()
        flash('Attendance marked successfully!', 'success')
    return redirect(url_for('history'))

# Attendance History Page
@app.route("/history")
@login_required
def history():
    # Get all attendance records for the current user
    user_attendance = Attendance.query.filter_by(user_id=current_user.id).all()
    return render_template('history.html', attendance_records=user_attendance)

# This is the main entry point to run the app
if __name__ == '__main__':
    with app.app_context():
        db.create_all() # Create database tables if they don't exist
        # Create a dummy event if none exist, for testing
        if not Event.query.first():
            dummy_event = Event(title="First Cyber Club Session", description="Introduction to Web Security.", is_active=True)
            db.session.add(dummy_event)
            db.session.commit()
    app.run(debug=True)