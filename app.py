from flask import Flask, request, render_template, flash, redirect, url_for, session, jsonify
import os
import re
import psycopg2
from psycopg2 import sql
import mimetypes
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.base import MIMEBase
from email.mime.audio import MIMEAudio
from email.mime.image import MIMEImage
from email.mime.application import MIMEApplication
from email import encoders
from dotenv import load_dotenv
from google_auth_oauthlib.flow import Flow
from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials
from googleapiclient.discovery import build
import base64
import logging
from datetime import timedelta
from urllib.parse import parse_qs, urlparse
from flask_cors import CORS
import requests

# Load environment variables
load_dotenv()

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Initialize Flask app
app = Flask(__name__)
app.secret_key = os.getenv('FLASK_SECRET_KEY', 'your-secret-key')
app.config['SESSION_PERMANENT'] = True
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=30)
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
app.config['SESSION_COOKIE_SECURE'] = True 
CORS(app, resources={
    r"/backend_service": {
        "origins": ["https://meet-sync-backend-1.vercel.app", "http://localhost:8080"],
        "allow_headers": ["Authorization", "Content-Type"],
        "methods": ["POST", "OPTIONS"],
        "supports_credentials": True
    }
}) 

# Database connection
def get_db_connection():
    try:
        conn = psycopg2.connect(os.getenv('DATABASE_URL'))
        return conn
    except Exception as e:
        logger.error(f"Database connection error: {e}")
        return None

# Create users table if not exists
def init_db():
    conn = get_db_connection()
    if conn:
        try:
            with conn.cursor() as cur:
                cur.execute("""
                    CREATE TABLE IF NOT EXISTS users (
                        id SERIAL PRIMARY KEY,
                        email VARCHAR(120) UNIQUE NOT NULL
                    );
                """)
                conn.commit()
        except Exception as e:
            logger.error(f"Error initializing database: {e}")
        finally:
            conn.close()

# Initialize database
init_db()

# OAuth 2.0 configuration
SCOPES = ['https://www.googleapis.com/auth/gmail.send']

def get_user_email_from_token(access_token):
    try:
        headers = {'Authorization': f'Bearer {access_token}'}
        response = requests.get('https://www.googleapis.com/oauth2/v3/userinfo', headers=headers)
        if response.status_code == 200:
            user_info = response.json()
            logger.debug(f"Userinfo response: {user_info}")
            return user_info.get('email', '')
        logger.error(f"Failed to fetch user email: {response.text}")
        return None
    except Exception as e:
        logger.error(f"Error fetching user email: {e}")
        return None

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
                return None
        else:
            logger.debug("No valid credentials, redirecting to authorize")
            return None
    try:
        service = build('gmail', 'v1', credentials=creds)
        logger.debug("Gmail service initialized successfully")
        return service
    except Exception as e:
        logger.error(f"Error building Gmail service: {e}")
        return None

def get_gmail_service_with_token(access_token):
    try:
        creds = Credentials(token=access_token, scopes=SCOPES)
        service = build('gmail', 'v1', credentials=creds)
        service.users().getProfile(userId='me').execute()
        logger.debug("Gmail service initialized with external token")
        return service
    except Exception as e:
        logger.error(f"Error building Gmail service with external token: {e}")
        return None

def create_email(sender_email, recipient_email, reply_to, subject, message, files=None):
    msg = MIMEMultipart()
    msg['From'] = sender_email
    msg['To'] = recipient_email
    if reply_to:
        msg['Reply-To'] = reply_to
    msg['Subject'] = subject
    msg.attach(MIMEText(message, 'plain'))

    if files:
        total_size = 0
        max_size = 35 * 1024 * 1024
        for file in files:
            if file and file.filename:
                try:
                    file_content = file.read()
                    file_size = len(file_content)
                    total_size += file_size
                    if total_size > max_size:
                        logger.warning(f"Total attachment size exceeds 35 MB: {total_size} bytes")
                        raise ValueError("Total attachment size exceeds Gmail's 35 MB limit.")
                    mime_type, _ = mimetypes.guess_type(file.filename)
                    if mime_type is None:
                        mime_type = 'application/octet-stream'
                    main_type, sub_type = mime_type.split('/', 1)
                    if main_type == 'text':
                        part = MIMEText(file_content, _subtype=sub_type, _charset='utf-8')
                    elif main_type == 'image':
                        part = MIMEImage(file_content, _subtype=sub_type)
                    elif main_type == 'audio':
                        part = MIMEAudio(file_content, _subtype=sub_type)
                    elif main_type == 'application':
                        part = MIMEApplication(file_content, _subtype=sub_type)
                    else:
                        part = MIMEBase(main_type, sub_type)
                        part.set_payload(file_content)
                        encoders.encode_base64(part)
                    part.add_header('Content-Disposition', f'attachment; filename="{file.filename}"')
                    msg.attach(part)
                    logger.debug(f"Attached file: {file.filename}, Size: {file_size} bytes")
                except Exception as e:
                    logger.error(f"Error attaching file {file.filename}: {e}")
                    raise ValueError(f"Failed to attach {file.filename}: {str(e)}")
                finally:
                    file.seek(0)
    try:
        raw = base64.urlsafe_b64encode(msg.as_bytes()).decode()
        logger.debug("Email message encoded successfully")
        return {'raw': raw}
    except Exception as e:
        logger.error(f"Error encoding email message: {e}")
        raise ValueError(f"Failed to encode email: {str(e)}")

def send_email(service, msg):
    try:
        result = service.users().messages().send(userId='me', body=msg).execute()
        logger.debug(f"Email sent successfully: {result}")
        return True
    except Exception as e:
        logger.error(f"Failed to send email: {str(e)}")
        raise Exception(f"Failed to send email: {str(e)}")

def is_valid_email(email):
    pattern = r'^[\w\.-]+@[\w\.-]+\.\w+$'
    return re.match(pattern, email) is not None

# Existing routes (login, register, authorize, oauth2callback, logout, clear_session, index) remain unchanged
# ... [Previous routes omitted for brevity] ...

@app.route('/backend_service', methods=['POST'])
def backend_service():
    logger.debug("Received request to /backend_service")
    auth_header = request.headers.get('Authorization')
    logger.debug(f"Authorization header: {auth_header}")
    if not auth_header or not auth_header.startswith('Bearer '):
        logger.error("Missing or invalid Authorization header")
        return jsonify({"error": "Missing or invalid Authorization header"}), 401

    access_token = auth_header.split(' ')[1]
    if not access_token:
        logger.error("No access token provided")
        return jsonify({"error": "No access token provided"}), 401

    try:
        data = request.get_json()
        logger.debug(f"Received JSON payload: {data}")
        if not isinstance(data, list) or not data:
            logger.error("Invalid JSON format: must be a non-empty list")
            return jsonify({"error": "Invalid JSON format: must be a non-empty list"}), 400

        email_data = data[0]
        email_type = email_data.get('type', 'email')
        recipient = email_data.get('recipient', '').strip()
        subject = email_data.get('subject', '').strip()
        body = email_data.get('body', '').strip()
        sender_email = email_data.get('sender_email', '').strip()
        logger.debug(f"Parsed email data: type={email_type}, recipient={recipient}, subject={subject}, sender_email={sender_email}")

        if email_type != 'email':
            logger.error(f"Unsupported type: {email_type}")
            return jsonify({"error": f"Unsupported type: {email_type}"}), 400

        if not recipient or not subject or not body or not sender_email:
            logger.error("Missing required fields: recipient, subject, body, or sender_email")
            return jsonify({"error": "Missing required fields: recipient, subject, body, or sender_email"}), 400

        if not is_valid_email(recipient) or not is_valid_email(sender_email):
            logger.error(f"Invalid email format: recipient={recipient}, sender_email={sender_email}")
            return jsonify({"error": "Invalid recipient or sender email"}), 400

    except Exception as e:
        logger.error(f"Error parsing JSON: {str(e)}")
        return jsonify({"error": "Invalid JSON payload"}), 400

    token_email = get_user_email_from_token(access_token)
    logger.debug(f"Token email: {token_email}")
    if not token_email:
        logger.error("Could not retrieve email from access token")
        return jsonify({"error": "Invalid or expired access token"}), 401
    if token_email != sender_email:
        logger.error(f"Sender email {sender_email} does not match token email {token_email}")
        return jsonify({"error": "Sender email does not match authenticated user"}), 403

    conn = get_db_connection()
    if conn:
        try:
            with conn.cursor() as cur:
                cur.execute("SELECT email FROM users WHERE email = %s", (sender_email,))
                user = cur.fetchone()
                logger.debug(f"Database query result for {sender_email}: {user}")
                if not user:
                    logger.error(f"Sender email not registered: {sender_email}")
                    return jsonify({"error": "Sender email not registered"}), 403
        except Exception as e:
            logger.error(f"Database error: {str(e)}")
            return jsonify({"error": "Database error"}), 500
        finally:
            conn.close()
    else:
        logger.error("Database connection failed")
        return jsonify({"error": "Database connection failed"}), 500

    service = get_gmail_service_with_token(access_token)
    if not service:
        logger.error("Failed to initialize Gmail service with provided token")
        return jsonify({"error": "Invalid or expired access token"}), 401

    try:
        msg = create_email(sender_email, recipient, None, subject, body, files=None)
        logger.debug("Email message created successfully")
        send_email(service, msg)
        logger.info(f"Email sent successfully to {recipient}")
        return jsonify({"message": "Email sent successfully"}), 200
    except ValueError as ve:
        logger.error(f"ValueError in email sending: {ve}")
        return jsonify({"error": str(ve)}), 400
    except Exception as e:
        logger.error(f"Email sending error: {str(e)}")
        return jsonify({"error": f"Failed to send email: {str(e)}"}), 500
    
if __name__ == '__main__':
    app.run()
