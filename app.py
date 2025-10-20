import os
from flask import Flask, render_template, request, redirect, url_for, flash, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_login import LoginManager, UserMixin, login_user, logout_user, current_user, login_required
from datetime import datetime
from functools import wraps

# --- APP & DATABASE CONFIGURATION ---
app = Flask(__name__)
app.config['SECRET_KEY'] = 'a_very_secret_key_change_this'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///site.db'
app.config['UPLOAD_FOLDER'] = 'static/profile_pics'
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

# --- ADMIN DECORATOR ---
# This protects routes so only admins can access them
def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or current_user.role != 'admin':
            flash("You do not have permission to access this page.", "danger")
            return redirect(url_for('home'))
        return f(*args, **kwargs)
    return decorated_function

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# --- DATABASE MODELS (TABLES) ---
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(60), nullable=False)
    branch = db.Column(db.String(50), nullable=False)
    year = db.Column(db.Integer, nullable=False)
    profile_pic = db.Column(db.String(20), nullable=False, default='default.jpg')
    role = db.Column(db.String(10), nullable=False, default='student') # student vs admin
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    attendance = db.relationship('Attendance', backref='attendee', lazy=True)

class Event(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    date = db.Column(db.DateTime, nullable=False)
    description = db.Column(db.Text, nullable=False)
    attendance = db.relationship('Attendance', backref='event', lazy=True)

class Attendance(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    event_id = db.Column(db.Integer, db.ForeignKey('event.id'), nullable=False)
    marked_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)

# --- USER ROUTES ---
@app.route("/")
def home():
    upcoming_events = Event.query.filter(Event.date >= datetime.utcnow()).order_by(Event.date.asc()).all()
    return render_template('index.html', events=upcoming_events)

@app.route("/register", methods=['GET', 'POST'])
def register():
    # ... (code is the same as before)
    if request.method == 'POST':
        name = request.form.get('name')
        email = request.form.get('email')
        password = request.form.get('password')
        branch = request.form.get('branch')
        year = request.form.get('year')
        if User.query.filter_by(email=email).first():
            flash('Email already exists. Please log in.', 'danger')
            return redirect(url_for('login'))
        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
        user = User(name=name, email=email, password=hashed_password, branch=branch, year=year)
        db.session.add(user)
        db.session.commit()
        flash('Your account has been created! You can now log in.', 'success')
        return redirect(url_for('login'))
    return render_template('register.html')

@app.route("/login", methods=['GET', 'POST'])
def login():
    # ... (code is the same as before)
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        user = User.query.filter_by(email=email).first()
        if user and bcrypt.check_password_hash(user.password, password):
            login_user(user, remember=True)
            flash('Login successful!', 'success')
            return redirect(url_for('profile'))
        else:
            flash('Login unsuccessful. Please check email and password.', 'danger')
    return render_template('login.html')

@app.route("/logout")
def logout():
    logout_user()
    return redirect(url_for('home'))

@app.route("/profile", methods=['GET', 'POST'])
@login_required
def profile():
    # ... (code is the same as before)
    if request.method == 'POST':
        current_user.name = request.form.get('name')
        current_user.branch = request.form.get('branch')
        current_user.year = request.form.get('year')
        db.session.commit()
        flash('Your profile has been updated!', 'success')
        return redirect(url_for('profile'))
    return render_template('profile.html', user=current_user)

@app.route("/history")
@login_required
def history():
    user_attendance = Attendance.query.filter_by(user_id=current_user.id).order_by(Attendance.marked_at.desc()).all()
    return render_template('history.html', attendance_records=user_attendance)

# --- ADMIN ROUTES ---
@app.route("/admin")
@login_required
@admin_required
def admin_dashboard():
    students = User.query.filter_by(role='student').order_by(User.name).all()
    events = Event.query.order_by(Event.date.desc()).all()
    return render_template('admin.html', students=students, events=events)

@app.route("/admin/add_event", methods=['GET', 'POST'])
@login_required
@admin_required
def add_event():
    if request.method == 'POST':
        title = request.form.get('title')
        description = request.form.get('description')
        date_str = request.form.get('date')
        date = datetime.strptime(date_str, '%Y-%m-%d')
        new_event = Event(title=title, description=description, date=date)
        db.session.add(new_event)
        db.session.commit()
        flash('Event created successfully!', 'success')
        return redirect(url_for('admin_dashboard'))
    return render_template('add_event.html')

# --- DATA & HELPER ROUTES ---
@app.route("/attendance-data")
@login_required
def attendance_data():
    total_events = Event.query.count()
    attended_count = Attendance.query.filter_by(user_id=current_user.id).count()
    missed_count = total_events - attended_count if total_events > attended_count else 0
    if total_events == 0:
        return jsonify({'attended': 0, 'missed': 0})
    return jsonify({'attended': attended_count, 'missed': missed_count})

@app.route("/make-admin/<email>")
def make_admin(email):
    # This is an insecure way to make an admin, for development purposes only!
    user = User.query.filter_by(email=email).first()
    if user:
        user.role = 'admin'
        db.session.commit()
        return f"User {user.name} is now an admin."
    return "User not found."

# --- CLI COMMAND TO INITIALIZE THE DATABASE ---
@app.cli.command("init-db")
def init_db_command():
    """Clears the existing data and creates new tables."""
    db.create_all()
    # Create a dummy event if none exist for testing
    if not Event.query.first():
        dummy_event = Event(title="First Cyber Club Session", description="Introduction to Web Security.", date=datetime.utcnow())
        db.session.add(dummy_event)
        db.session.commit()
    print("Initialized the database.")

# This block is only needed if you were to run 'python app.py' directly
if __name__ == '__main__':
    app.run(debug=True)

