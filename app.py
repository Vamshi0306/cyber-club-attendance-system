import os
import secrets
from flask import Flask, render_template, request, redirect, url_for, flash, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_login import LoginManager, UserMixin, login_user, logout_user, current_user, login_required
from datetime import datetime
from functools import wraps
from PIL import Image

# --- APP & DATABASE CONFIGURATION ---
app = Flask(__name__)
app.config['SECRET_KEY'] = 'a_very_secret_key_change_this'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///site.db'
app.config['UPLOAD_FOLDER'] = 'static/profile_pics'
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

# --- NO API KEYS OR INVITE CODES NEEDED ---

db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'
login_manager.login_message_category = 'info'

# --- HELPER FUNCTIONS ---
def save_picture(form_picture):
    random_hex = secrets.token_hex(8)
    _, f_ext = os.path.splitext(form_picture.filename)
    picture_fn = random_hex + f_ext
    picture_path = os.path.join(app.root_path, app.config['UPLOAD_FOLDER'], picture_fn)

    output_size = (125, 125)
    i = Image.open(form_picture)
    i.thumbnail(output_size)
    i.save(picture_path)
    return picture_fn

# --- DECORATORS ---
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

# --- DATABASE MODELS ---
# We re-added 'is_verified' for the admin approval
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(60), nullable=False)
    branch = db.Column(db.String(50), nullable=False)
    year = db.Column(db.Integer, nullable=False)
    profile_pic = db.Column(db.String(20), nullable=False, default='default.jpg')
    role = db.Column(db.String(10), nullable=False, default='student')
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    is_verified = db.Column(db.Boolean, nullable=False, default=False) # False by default
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

# --- AUTHENTICATION & USER ROUTES ---
@app.route("/")
def home():
    upcoming_events = []
    if current_user.is_authenticated:
        upcoming_events = Event.query.filter(Event.date >= datetime.utcnow()).order_by(Event.date.asc()).all()
        attended_event_ids = [att.event_id for att in current_user.attendance]
        return render_template('index.html', events=upcoming_events, attended_event_ids=attended_event_ids)
    return render_template('index.html')

@app.route("/register", methods=['GET', 'POST'])
def register():
    # ** NEW: ADMIN APPROVAL LOGIC **
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    if request.method == 'POST':
        name = request.form.get('name')
        email = request.form.get('email')
        password = request.form.get('password')
        branch = request.form.get('branch')
        year = request.form.get('year')
        profile_pic = request.files.get('profile_pic')

        existing_user = User.query.filter_by(email=email).first()
        if existing_user:
            flash('Email already exists. Please log in.', 'danger')
            return redirect(url_for('login'))

        picture_file = 'default.jpg'
        if profile_pic:
            picture_file = save_picture(profile_pic)

        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
        
        # Create user as 'is_verified=False' (pending)
        new_user = User(name=name, email=email, password=hashed_password, branch=branch, year=year, profile_pic=picture_file, is_verified=False)
        db.session.add(new_user)
        db.session.commit()

        flash('Registration successful! Your account is now pending admin approval.', 'success')
        return redirect(url_for('login'))

    return render_template('register.html')

@app.route("/login", methods=['GET', 'POST'])
def login():
    # ** NEW: CHECK FOR APPROVAL **
    if current_user.is_authenticated:
        return redirect(url_for('home'))
        
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        user = User.query.filter_by(email=email).first()

        if user and bcrypt.check_password_hash(user.password, password):
            # NEW CHECK: Is the user approved?
            if not user.is_verified:
                flash('Your account is still pending admin approval. Please wait.', 'warning')
                return redirect(url_for('login'))
            
            # User is approved, log them in
            login_user(user, remember=True)
            flash('Login successful!', 'success')
            return redirect(url_for('home'))
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
    if request.method == 'POST':
        current_user.name = request.form.get('name')
        current_user.branch = request.form.get('branch')
        current_user.year = request.form.get('year')
        if request.files.get('profile_pic'):
            picture_file = save_picture(request.files['profile_pic'])
            current_user.profile_pic = picture_file
        db.session.commit()
        flash('Your profile has been updated!', 'success')
        return redirect(url_for('profile'))
    image_file = url_for('static', filename=f'profile_pics/{current_user.profile_pic}')
    return render_template('profile.html', user=current_user, image_file=image_file)

# --- ATTENDANCE ROUTES ---
@app.route("/mark_attendance/<int:event_id>")
@login_required
def mark_attendance(event_id):
    event = Event.query.get_or_404(event_id)
    already_marked = Attendance.query.filter_by(user_id=current_user.id, event_id=event.id).first()
    if already_marked:
        flash('You have already marked attendance for this session.', 'info')
    else:
        attendance = Attendance(user_id=current_user.id, event_id=event.id)
        db.session.add(attendance)
        db.session.commit()
        flash(f'Attendance marked for "{event.title}"!', 'success')
    return redirect(url_for('home'))
    
# --- ADMIN ROUTES ---
@app.route("/admin")
@login_required
@admin_required
def admin_dashboard():
    # NEW: Get pending users
    pending_users = User.query.filter_by(is_verified=False, role='student').order_by(User.created_at.desc()).all()
    
    total_students = User.query.filter_by(role='student', is_verified=True).count()
    total_events = Event.query.count()
    total_attendance = Attendance.query.count()
    students = User.query.filter_by(role='student', is_verified=True).order_by(User.name).all()
    events = Event.query.order_by(Event.date.desc()).all()
    
    return render_template('admin.html', students=students, events=events, 
                           pending_users=pending_users, # Pass pending users to template
                           total_students=total_students, total_events=total_events, total_attendance=total_attendance)

# NEW: Route to approve a user
@app.route("/admin/approve/<int:user_id>")
@login_required
@admin_required
def approve_user(user_id):
    user = User.query.get_or_404(user_id)
    user.is_verified = True
    db.session.commit()
    flash(f"User {user.name} has been approved.", "success")
    return redirect(url_for('admin_dashboard'))

# NEW: Route to deny (delete) a user
@app.route("/admin/deny/<int:user_id>")
@login_required
@admin_required
def deny_user(user_id):
    user = User.query.get_or_404(user_id)
    # Delete profile picture if it's not the default
    if user.profile_pic != 'default.jpg':
        try:
            os.remove(os.path.join(app.root_path, app.config['UPLOAD_FOLDER'], user.profile_pic))
        except FileNotFoundError:
            pass # Ignore if pic is already missing
    db.session.delete(user)
    db.session.commit()
    flash(f"User {user.name} has been denied and deleted.", "success")
    return redirect(url_for('admin_dashboard'))

@app.route("/admin/event/add", methods=['GET', 'POST'])
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

@app.route("/admin/event/<int:event_id>/delete", methods=['POST'])
@login_required
@admin_required
def delete_event(event_id):
    event = Event.query.get_or_404(event_id)
    Attendance.query.filter_by(event_id=event.id).delete()
    db.session.delete(event)
    db.session.commit()
    flash('Event and all its attendance records have been deleted!', 'success')
    return redirect(url_for('admin_dashboard'))

# --- DATA & HELPER ROUTES ---
@app.route("/attendance-data")
@login_required
def attendance_data():
    total_events = Event.query.count()
    attended_count = Attendance.query.filter_by(user_id=current_user.id).count()
    missed_count = total_events - attended_count if total_events > attended_count else 0
    return jsonify({'attended': attended_count, 'missed': missed_count, 'total': total_events})

# --- CLI COMMAND TO INITIALIZE DB ---
@app.cli.command("init-db")
def init_db_command():
    """Clears the existing data and creates new tables."""
    db.create_all()
    print("Initialized the database.")
    if not User.query.filter_by(role='admin').first():
        email = 'buddaramvamshidhar@gmail.com' 
        password = 'password'       
        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
        # Admin must be 'is_verified=True' to be able to log in
        admin_user = User(name='Admin', email=email, password=hashed_password, branch='SYSTEM', year=0, role='admin', is_verified=True)
        db.session.add(admin_user)
        db.session.commit()
        print(f"Admin user created with email: {email} and password: {password}")
