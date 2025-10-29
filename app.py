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
    url = "https://api
