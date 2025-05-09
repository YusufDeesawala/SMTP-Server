from flask import Flask, request, render_template, flash, redirect, url_for, session
from flask_sqlalchemy import SQLAlchemy
import os
import re
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.base import MIMEBase
from email import encoders
from dotenv import load_dotenv
from google_auth_oauthlib.flow import InstalledAppFlow
from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials
from googleapiclient.discovery import build
import base64

# Load environment variables from .env file
load_dotenv()

app = Flask(__name__)
app.secret_key = os.getenv('FLASK_SECRET_KEY', 'your-secret-key')

# SQLAlchemy configuration
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URI', 'sqlite:///email_app.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

# User model
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)

# Create database tables
with app.app_context():
    db.create_all()

# OAuth 2.0 configuration
SCOPES = ['https://www.googleapis.com/auth/gmail.send']
CLIENT_SECRETS_FILE = 'credentials.json'
REDIRECT_URI = 'http://localhost:5000/oauth2callback'  # Fixed redirect URI for local testing

def get_gmail_service():
    creds = None
    if 'token' in session:
        try:
            creds = Credentials.from_authorized_user_info(eval(session['token']), SCOPES)
        except Exception as e:
            app.logger.error(f"Error loading credentials: {e}")
            session.pop('token', None)
    if not creds or not creds.valid:
        if creds and creds.expired and creds.refresh_token:
            try:
                creds.refresh(Request())
                session['token'] = creds.to_json()
            except Exception as e:
                app.logger.error(f"Error refreshing token: {e}")
                session.pop('token', None)
                return None
        else:
            flash('Please authorize Gmail access.', 'error')
            return None
    return build('gmail', 'v1', credentials=creds)

def create_email(sender_email, recipient_email, reply_to, subject, message, files):
    msg = MIMEMultipart()
    msg['From'] = sender_email
    msg['To'] = recipient_email
    if reply_to:
        msg['Reply-To'] = reply_to
    msg['Subject'] = subject
    msg.attach(MIMEText(message, 'plain'))
    
    for file in files:
        if file and file.filename:
            filename = file.filename
            attachment = MIMEBase('application', 'octet-stream')
            attachment.set_payload(file.read())
            encoders.encode_base64(attachment)
            attachment.add_header('Content-Disposition', f'attachment; filename="{filename}"')
            msg.attach(attachment)
    
    raw = base64.urlsafe_b64encode(msg.as_bytes()).decode()
    return {'raw': raw}

def send_email(service, msg):
    try:
        service.users().messages().send(userId='me', body=msg).execute()
        return True
    except Exception as e:
        raise Exception(f"Failed to send email: {e}")

def is_valid_email(email):
    pattern = r'^[\w\.-]+@[\w\.-]+\.\w+$'
    return re.match(pattern, email) is not None

@app.route('/login', methods=['GET', 'POST'])
def login():
    if 'user_id' in session:
        return redirect(url_for('index'))
    
    if request.method == 'POST':
        email = request.form.get('email').strip()
        if not is_valid_email(email):
            flash('Invalid email format.', 'error')
            return redirect(url_for('login'))
        
        user = User.query.filter_by(email=email).first()
        if user:
            session['user_id'] = user.id
            session['user_email'] = user.email
            flash('Logged in successfully! Please authorize Gmail access.', 'success')
            return redirect(url_for('authorize'))
        else:
            flash('Email not registered. Please register.', 'error')
    
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if 'user_id' in session:
        return redirect(url_for('index'))
    
    if request.method == 'POST':
        email = request.form.get('email').strip()
        if not is_valid_email(email):
            flash('Invalid email format.', 'error')
            return redirect(url_for('register'))
        
        if User.query.filter_by(email=email).first():
            flash('Email already registered.', 'error')
            return redirect(url_for('register'))
        
        new_user = User(email=email)
        db.session.add(new_user)
        db.session.commit()
        flash('Registration successful! Please log in.', 'success')
        return redirect(url_for('login'))
    
    return render_template('register.html')

@app.route('/authorize')
def authorize():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    try:
        flow = InstalledAppFlow.from_client_secrets_file(CLIENT_SECRETS_FILE, SCOPES)
        flow.redirect_uri = REDIRECT_URI
        authorization_url, state = flow.authorization_url(
            access_type='offline',
            include_granted_scopes='true'
        )
        session['state'] = state
        return redirect(authorization_url)
    except Exception as e:
        flash(f"Error initiating OAuth flow: {str(e)}", 'error')
        return redirect(url_for('login'))

@app.route('/oauth2callback')
def oauth2callback():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    state = session.get('state')
    if not state:
        flash('Invalid OAuth state. Please try again.', 'error')
        return redirect(url_for('authorize'))
    
    try:
        flow = InstalledAppFlow.from_client_secrets_file(CLIENT_SECRETS_FILE, SCOPES, state=state)
        flow.redirect_uri = REDIRECT_URI
        flow.fetch_token(authorization_response=request.url)
        session['token'] = flow.credentials.to_json()
        flash('Gmail access authorized!', 'success')
        return redirect(url_for('index'))
    except Exception as e:
        flash(f"OAuth error: {str(e)}", 'error')
        return redirect(url_for('authorize'))

@app.route('/logout')
def logout():
    session.pop('user_id', None)
    session.pop('user_email', None)
    session.pop('token', None)
    session.pop('state', None)
    flash('Logged out successfully.', 'success')
    return redirect(url_for('login'))

@app.route('/', methods=['GET', 'POST'])
def index():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    user = User.query.get(session['user_id'])
    if not user:
        session.pop('user_id', None)
        session.pop('user_email', None)
        session.pop('token', None)
        flash('User not found. Please log in again.', 'error')
        return redirect(url_for('login'))
    
    if request.method == 'POST':
        recipient_email = request.form.get('recipient_email').strip()
        reply_to = request.form.get('reply_to').strip()
        subject = request.form.get('subject').strip()
        message = request.form.get('message').strip()
        files = request.files.getlist('attachments')
        
        if not is_valid_email(recipient_email):
            flash('Invalid recipient email address.', 'error')
            return redirect(url_for('index'))
        if reply_to and not is_valid_email(reply_to):
            flash('Invalid reply-to email address.', 'error')
            return redirect(url_for('index'))
        
        try:
            service = get_gmail_service()
            if not service:
                return redirect(url_for('authorize'))
            msg = create_email(user.email, recipient_email, reply_to, subject, message, files)
            if send_email(service, msg):
                flash('Email sent successfully!', 'success')
            else:
                flash('Invalid recipient email.', 'error')
        except Exception as e:
            flash(f"An error occurred: {str(e)}", 'error')
        
        return redirect(url_for('index'))
    
    return render_template('index.html', user_email=user.email)

if __name__ == '__main__':
    app.run(debug=True, port=5000)