import os
import secrets
from flask import Flask, render_template, request, redirect, url_for, flash, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_login import LoginManager, UserMixin, login_user, logout_user, current_user, login_required
from datetime import datetime
from functools import wraps
from PIL import Image

# --- Imports for SendGrid/Email Fix ---
import requests
import json
import urllib3

# --- APP & DATABASE CONFIGURATION ---
app = Flask(__name__)
app.config['SECRET_KEY'] = 'a_very_secret_key_change_this'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///site.db'
app.config['UPLOAD_FOLDER'] = 'static/profile_pics'
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

# --- SENDGRID CONFIGURATION ---
# !!! CRITICAL: YOU MUST PASTE YOUR WORKING API KEY HERE !!!
SENDGRID_API_KEY = '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'
# !!! CRITICAL: YOU MUST PUT YOUR VERIFIED SENDER EMAIL HERE !!!
VERIFIED_SENDER_EMAIL = 'buddaramvamshidhar06@gmail.com'

db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'
login_manager.login_message_category = 'info' # Use Bootstrap 'info' class for messages

# --- CONTEXT PROCESSOR ---
# Makes 'now' available in all templates for the current year
@app.context_processor
def inject_now():
    return {'now': datetime.utcnow}

# --- HELPER FUNCTIONS ---
# ... (rest of your app.py code) ...

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

def send_otp_email(recipient_email, otp, name="User"):
    """Sends OTP using SendGrid via raw requests to BYPASS SSL VERIFICATION."""
    url = "https://api.sendgrid.com/v3/mail/send"
    headers = {
        "Authorization": f"Bearer {SENDGRID_API_KEY}",
        "Content-Type": "application/json"
    }
    data = {
        "personalizations": [{"to": [{"email": recipient_email}], "subject": "Your Cyber Club Verification Code"}],
        "from": {"email": VERIFIED_SENDER_EMAIL, "name": "Cyber Club Admin"},
        "content": [{"type": "text/html", "value": f'<p>Hello {name},</p><p>Your One-Time Password (OTP) is: <strong>{otp}</strong></p><p>This code will expire in 10 minutes.</p>'}]
    }
    try:
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        response = requests.post(url, headers=headers, data=json.dumps(data), verify=False)
        if 200 <= response.status_code < 300:
            return True
        else:
            print(f"Error from SendGrid API: {response.status_code} - {response.text}")
            return False
    except Exception as e:
        print(f"Error sending email: {e}")
        return False

# --- DECORATORS ---
def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or current_user.role != 'admin':
            flash("You do not have permission to access this page.", "warning") # Changed to warning
            return redirect(url_for('home'))
        return f(*args, **kwargs)
    return decorated_function

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# --- DATABASE MODELS ---
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    # NEW: Roll Number field
    roll_number = db.Column(db.String(20), unique=True, nullable=False)
    password = db.Column(db.String(60), nullable=False)
    branch = db.Column(db.String(50), nullable=False)
    year = db.Column(db.Integer, nullable=False)
    profile_pic = db.Column(db.String(20), nullable=False, default='default.jpg')
    role = db.Column(db.String(10), nullable=False, default='student')
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    # ADDED BACK: OTP fields
    is_verified = db.Column(db.Boolean, nullable=False, default=False)
    otp = db.Column(db.String(6), nullable=True)
    otp_generated_at = db.Column(db.DateTime, nullable=True)
    attendance = db.relationship('Attendance', backref='attendee', lazy=True)
    resources = db.relationship('Resource', backref='author', lazy=True)

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

class Resource(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text, nullable=False)
    link = db.Column(db.String(500), nullable=True)
    created_by_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)

# --- AUTHENTICATION & USER ROUTES ---
@app.route("/")
def home():
    if current_user.is_authenticated:
        if current_user.role == 'admin':
            return redirect(url_for('admin_dashboard'))
        upcoming_events = Event.query.filter(Event.date >= datetime.utcnow()).order_by(Event.date.asc()).all()
        attended_event_ids = [att.event_id for att in current_user.attendance]
        return render_template('index.html', events=upcoming_events, attended_event_ids=attended_event_ids)
    return render_template('index.html') # Show basic landing page if not logged in

@app.route("/register", methods=['GET', 'POST'])
def register():
    # ** OTP LOGIC RE-ADDED, ADMIN APPROVAL REMOVED **
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    if request.method == 'POST':
        name = request.form.get('name')
        email = request.form.get('email')
        roll_number = request.form.get('roll_number') # Get roll number
        password = request.form.get('password')
        branch = request.form.get('branch')
        year = request.form.get('year')
        profile_pic = request.files.get('profile_pic')

        # Check existing email or roll number
        existing_user_email = User.query.filter_by(email=email).first()
        existing_user_roll = User.query.filter_by(roll_number=roll_number).first()
        if existing_user_email:
            flash('Email already exists. Please log in.', 'danger')
            return redirect(url_for('login'))
        if existing_user_roll:
            flash('Roll Number already exists. Please contact an admin if this is incorrect.', 'danger')
            return redirect(url_for('register'))

        picture_file = 'default.jpg'
        if profile_pic:
            picture_file = save_picture(profile_pic)

        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
        otp = secrets.token_hex(3).upper()

        # Create user with OTP fields
        new_user = User(name=name, email=email, roll_number=roll_number, password=hashed_password, branch=branch, year=year, profile_pic=picture_file, otp=otp, otp_generated_at=datetime.utcnow(), is_verified=False)
        db.session.add(new_user)
        db.session.commit()

        if send_otp_email(email, otp, name):
            flash('Registration successful! Please check your email for a verification code.', 'success')
            return redirect(url_for('verify_otp', email=email))
        else:
            flash('Could not send verification email. Please contact an admin.', 'danger')
            # Optionally, you might want to delete the user here if email fails
            # db.session.delete(new_user)
            # db.session.commit()
            return redirect(url_for('register'))

    return render_template('register.html')

@app.route("/verify_otp/<email>", methods=['GET', 'POST'])
def verify_otp(email):
    # ** RE-ADDED **
    user = User.query.filter_by(email=email).first_or_404()
    if user.is_verified and user.otp is None: # Allow re-verification if OTP exists (for login)
         flash('Account already verified. Please log in.', 'info')
         return redirect(url_for('login'))

    if request.method == 'POST':
        entered_otp = request.form.get('otp')

        # Check for OTP expiration (10 minutes)
        if user.otp_generated_at is None: # Should not happen, but safety check
             flash('OTP error. Please try logging in again.', 'danger')
             return redirect(url_for('login'))
        time_diff = datetime.utcnow() - user.otp_generated_at
        if time_diff.total_seconds() > 600:
            flash('OTP has expired. Please try logging in again to get a new one.', 'danger')
            return redirect(url_for('login'))

        if user.otp == entered_otp:
            was_already_verified = user.is_verified # Check if this was a login verification
            user.is_verified = True
            user.otp = None # Clear OTP after use
            user.otp_generated_at = None # Clear generation time
            db.session.commit()

            login_user(user, remember=True)
            if not was_already_verified:
                 flash('Email verified successfully! You are now logged in.', 'success')
            else:
                 flash('Logged in successfully!', 'success')
            return redirect(url_for('home'))
        else:
            flash('Invalid OTP. Please try again.', 'danger')

    # Add safety check - if user is verified but somehow landed here w/o OTP, redirect
    if user.is_verified and user.otp is None:
         return redirect(url_for('login'))

    return render_template('verify_otp.html', email=email)

@app.route("/login", methods=['GET', 'POST'])
def login():
    # ** OTP LOGIC RE-ADDED **
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        user = User.query.filter_by(email=email).first()

        if user and bcrypt.check_password_hash(user.password, password):
            # Send OTP on every login
            otp = secrets.token_hex(3).upper()
            user.otp = otp
            user.otp_generated_at = datetime.utcnow()
            db.session.commit()
            if send_otp_email(user.email, otp, user.name):
                flash('Please check your email for a login verification code.', 'info')
                return redirect(url_for('verify_otp', email=user.email))
            else:
                flash('Could not send verification email. Please try again or contact an admin.', 'danger')
                return redirect(url_for('login'))
        else:
            flash('Login unsuccessful. Please check email and password.', 'danger')

    return render_template('login.html')

@app.route("/logout")
def logout():
    logout_user()
    flash('You have been logged out.', 'info') # Changed to info
    return redirect(url_for('login'))

@app.route("/profile", methods=['GET', 'POST'])
@login_required
def profile():
    if request.method == 'POST':
        current_user.name = request.form.get('name')
        # Roll number should generally not be editable, but check requirements
        # current_user.roll_number = request.form.get('roll_number')
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

@app.route("/resources")
@login_required
def resources():
    all_resources = Resource.query.order_by(Resource.created_at.desc()).all()
    return render_template('resources.html', resources=all_resources)

# --- ATTENDANCE ROUTES ---
@app.route("/mark_attendance/<int:event_id>")
@login_required
def mark_attendance(event_id):
    event = Event.query.get_or_404(event_id)
    already_marked = Attendance.query.filter_by(user_id=current_user.id, event_id=event.id).first()
    if already_marked:
        flash('You have already marked attendance for this session.', 'secondary') # Changed color
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
    # ** PENDING APPROVALS REMOVED **
    total_students = User.query.filter_by(role='student', is_verified=True).count()
    total_events = Event.query.count()
    total_attendance = Attendance.query.count()
    events = Event.query.order_by(Event.date.desc()).all()
    all_resources = Resource.query.order_by(Resource.created_at.desc()).all()
    approved_students = User.query.filter_by(role='student', is_verified=True).order_by(User.name).all() # Added list of approved students

    return render_template('admin.html', events=events,
                           all_resources=all_resources,
                           approved_students=approved_students, # Pass approved students
                           total_students=total_students, total_events=total_events, total_attendance=total_attendance)

# ** APPROVAL ROUTES REMOVED **
# /admin/approve/<int:user_id> REMOVED
# /admin/deny/<int:user_id> REMOVED

@app.route("/admin/event_report/<int:event_id>")
@login_required
@admin_required
def event_report(event_id):
    event = Event.query.get_or_404(event_id)
    all_students = User.query.filter_by(role='student', is_verified=True).all()
    attendee_ids = [a.user_id for a in event.attendance]
    attendees = [student for student in all_students if student.id in attendee_ids]
    absentees = [student for student in all_students if student.id not in attendee_ids]
    return render_template('event_report.html', event=event, attendees=attendees, absentees=absentees)

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
    flash('Event deleted.', 'success') # Simplified message
    return redirect(url_for('admin_dashboard'))

@app.route("/admin/resource/add", methods=['GET', 'POST'])
@login_required
@admin_required
def add_resource():
    if request.method == 'POST':
        title = request.form.get('title')
        description = request.form.get('description')
        link = request.form.get('link')
        new_resource = Resource(title=title, description=description, link=link, author=current_user)
        db.session.add(new_resource)
        db.session.commit()
        flash('New resource added!', 'success')
        return redirect(url_for('admin_dashboard'))
    return render_template('add_resource.html')

@app.route("/admin/resource/<int:resource_id>/delete", methods=['POST'])
@login_required
@admin_required
def delete_resource(resource_id):
    resource = Resource.query.get_or_404(resource_id)
    db.session.delete(resource)
    db.session.commit()
    flash('Resource deleted.', 'success') # Simplified message
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
    # Ensure admin exists and is verified
    admin_email = 'buddaramvamshidhar@gmail.com'
    if not User.query.filter_by(email=admin_email).first():
        password = 'password'
        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
        admin_user = User(name='Admin', email=admin_email, roll_number='ADMIN001', password=hashed_password, branch='SYSTEM', year=0, role='admin', is_verified=True)
        db.session.add(admin_user)
        db.session.commit()
        print(f"Admin user created with email: {admin_email} and password: {password}")
    else:
        # Ensure existing admin is verified
        admin = User.query.filter_by(email=admin_email).first()
        if not admin.is_verified:
            admin.is_verified = True
            db.session.commit()
            print(f"Ensured admin user {admin_email} is verified.")


