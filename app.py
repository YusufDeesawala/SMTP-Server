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
import logging
from datetime import timedelta
from urllib.parse import parse_qs, urlparse

# Allow HTTP for localhost during OAuth (for local testing only)
os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'

# Configure logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

# Initialize Flask app
app = Flask(__name__)
app.secret_key = os.getenv('FLASK_SECRET_KEY', 'your-secret-key')
app.config['SESSION_PERMANENT'] = True
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=30)
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
app.config['SESSION_COOKIE_SECURE'] = False  # False for local HTTP testing

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
REDIRECT_URI = os.getenv('REDIRECT_URI', 'http://localhost:5000/oauth2callback')  # Configurable for HTTPS

def get_gmail_service():
    creds = None
    if 'token' in session:
        try:
            creds = Credentials.from_authorized_user_info(eval(session['token']), SCOPES)
            logger.debug("Loaded credentials from session")
        except Exception as e:
            logger.error(f"Error loading credentials: {e}")
            session.pop('token', None)
    if not creds or not creds.valid:
        if creds and creds.expired and creds.refresh_token:
            try:
                logger.debug("Attempting to refresh OAuth token")
                creds.refresh(Request())
                session['token'] = creds.to_json()
                session.modified = True
                logger.debug("Refreshed OAuth token successfully")
            except Exception as e:
                logger.error(f"Error refreshing token: {e}")
                session.pop('token', None)
                flash(f"Token refresh failed: {str(e)}. Please reauthorize.", 'error')
                return None
        else:
            logger.debug("No valid credentials, redirecting to authorize")
            flash('Please authorize Gmail access.', 'error')
            return None
    try:
        service = build('gmail', 'v1', credentials=creds)
        logger.debug("Gmail service initialized successfully")
        return service
    except Exception as e:
        logger.error(f"Error building Gmail service: {e}")
        flash(f"Failed to initialize Gmail service: {str(e)}", 'error')
        return None

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
        logger.debug("Email sent successfully")
        return True
    except Exception as e:
        logger.error(f"Failed to send email: {e}")
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
            session.permanent = True
            session.modified = True
            logger.debug(f"User logged in: {email}, Session: {session}")
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
        logger.debug(f"User registered: {email}")
        flash('Registration successful! Please log in.', 'success')
        return redirect(url_for('login'))
    
    return render_template('register.html')

@app.route('/authorize')
def authorize():
    if 'user_id' not in session:
        logger.debug("No user_id in session, redirecting to login")
        return redirect(url_for('login'))
    
    try:
        flow = InstalledAppFlow.from_client_secrets_file(CLIENT_SECRETS_FILE, SCOPES)
        flow.redirect_uri = REDIRECT_URI
        authorization_url, state = flow.authorization_url(
            access_type='offline',
            include_granted_scopes='true',
            prompt='consent'
        )
        session['state'] = state
        session.modified = True
        logger.debug(f"Generated authorization URL: {authorization_url}, State: {state}")
        return redirect(authorization_url)
    except Exception as e:
        logger.error(f"Error initiating OAuth flow: {e}")
        flash(f"Error initiating Gmail authorization: {str(e)}", 'error')
        return redirect(url_for('login'))

@app.route('/oauth2callback')
def oauth2callback():
    if 'user_id' not in session:
        logger.debug("No user_id in session at callback, redirecting to login")
        flash('Session expired. Please log in again.', 'error')
        return redirect(url_for('login'))
    
    # Check for error in Google's response
    parsed_url = urlparse(request.url)
    query_params = parse_qs(parsed_url.query)
    if 'error' in query_params:
        error = query_params['error'][0]
        logger.error(f"Google OAuth error: {error}")
        flash(f"Google authorization failed: {error}. Please try again.", 'error')
        return redirect(url_for('login'))
    
    state = session.get('state')
    response_state = query_params.get('state', [None])[0]
    if not state or state != response_state:
        logger.error(f"State mismatch. Session state: {state}, Response state: {response_state}")
        flash('Invalid OAuth state. Please try again.', 'error')
        session.clear()
        return redirect(url_for('login'))
    
    try:
        flow = InstalledAppFlow.from_client_secrets_file(CLIENT_SECRETS_FILE, SCOPES)
        flow.redirect_uri = REDIRECT_URI
        logger.debug(f"Fetching token with response URL: {request.url}")
        flow.fetch_token(authorization_response=request.url)
        credentials = flow.credentials
        session['token'] = credentials.to_json()
        session.modified = True
        logger.debug("OAuth token fetched and stored in session")
        session.pop('state', None)  # Clear state after use
        flash('Gmail access authorized!', 'success')
        return redirect(url_for('index'))
    except Exception as e:
        logger.error(f"OAuth callback error: {str(e)}")
        flash(f"Authorization failed: {str(e)}. Please check your Google Cloud Console settings and try again.", 'error')
        return redirect(url_for('login'))

@app.route('/logout')
def logout():
    session.clear()
    logger.debug("User logged out, session cleared")
    flash('Logged out successfully.', 'success')
    return redirect(url_for('login'))

@app.route('/clear_session')
def clear_session():
    session.clear()
    logger.debug("Session cleared via /clear_session")
    flash('Session cleared.', 'success')
    return redirect(url_for('login'))

@app.route('/', methods=['GET', 'POST'])
def index():
    if 'user_id' not in session:
        logger.debug("No user_id in session, redirecting to login")
        return redirect(url_for('login'))
    
    user = User.query.get(session['user_id'])
    if not user:
        session.clear()
        logger.debug("User not found, session cleared")
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
                logger.debug("No Gmail service, redirecting to authorize")
                return redirect(url_for('authorize'))
            msg = create_email(user.email, recipient_email, reply_to, subject, message, files)
            if send_email(service, msg):
                flash('Email sent successfully!', 'success')
            else:
                flash('Invalid recipient email.', 'error')
        except Exception as e:
            logger.error(f"Email sending error: {e}")
            flash(f"An error occurred: {str(e)}", 'error')
        
        return redirect(url_for('index'))
    
    return render_template('index.html', user_email=user.email)

if __name__ == '__main__':
    app.run(debug=True, port=5000)