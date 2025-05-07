from flask import Flask, request, render_template, flash, redirect, url_for, session
import smtplib
import socket
import os
from pymongo import MongoClient
import bcrypt
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.base import MIMEBase
from email import encoders
import re

app = Flask(__name__)
app.secret_key = os.getenv('FLASK_SECRET_KEY', 'your-secret-key')  # Load secret key from env

# MongoDB setup
mongo_uri = os.getenv('MONGO_URI')
if not mongo_uri:
    raise ValueError("MONGO_URI must be set in environment variables")
client = MongoClient(mongo_uri)
db = client['email_app']
users_collection = db['users']

def setup_server():
    try:
        server = smtplib.SMTP(host='smtp.gmail.com', port=587)
        server.starttls()
        return server
    except Exception as e:
        raise Exception(f"Failed to set up server: {e}")

def login_smtp(server, email, app_password):
    try:
        server.login(email, app_password)
        return True
    except smtplib.SMTPAuthenticationError:
        return False

def add_attachment(msg, file):
    filename = file.filename
    attachment = MIMEBase('application', 'octet-stream')
    attachment.set_payload(file.read())
    encoders.encode_base64(attachment)
    attachment.add_header('Content-Disposition', f'attachment; filename="{filename}"')
    msg.attach(attachment)

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
            add_attachment(msg, file)
    
    return msg

def send_email(server, msg):
    try:
        server.send_message(msg)
        return True
    except smtplib.SMTPRecipientsRefused:
        return False
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
        app_password = request.form.get('app_password').strip()
        
        if not is_valid_email(email):
            flash('Invalid email format.', 'error')
            return redirect(url_for('login'))
        
        user = users_collection.find_one({'email': email})
        if user and bcrypt.checkpw(app_password.encode('utf-8'), user['app_password']):
            session['user_id'] = str(user['_id'])
            flash('Logged in successfully!', 'success')
            return redirect(url_for('index'))
        else:
            flash('Invalid email or App Password.', 'error')
    
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if 'user_id' in session:
        return redirect(url_for('index'))
    
    if request.method == 'POST':
        email = request.form.get('email').strip()
        app_password = request.form.get('app_password').strip()
        
        if not is_valid_email(email):
            flash('Invalid email format.', 'error')
            return redirect(url_for('register'))
        
        if users_collection.find_one({'email': email}):
            flash('Email already registered.', 'error')
            return redirect(url_for('register'))
        
        hashed_password = bcrypt.hashpw(app_password.encode('utf-8'), bcrypt.gensalt())
        users_collection.insert_one({
            'email': email,
            'app_password': hashed_password
        })
        flash('Registration successful! Please log in.', 'success')
        return redirect(url_for('login'))
    
    return render_template('register.html')

@app.route('/logout')
def logout():
    session.pop('user_id', None)
    flash('Logged out successfully.', 'success')
    return redirect(url_for('login'))

@app.route('/', methods=['GET', 'POST'])
def index():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    user = users_collection.find_one({'_id': session['user_id']})
    if not user:
        session.pop('user_id', None)
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
            server = setup_server()
            if not login_smtp(server, user['email'], request.form.get('app_password').strip()):
                flash('Authentication failed. Check App Password.', 'error')
                return redirect(url_for('index'))
            
            msg = create_email(user['email'], recipient_email, reply_to, subject, message, files)
            if send_email(server, msg):
                flash('Email sent successfully!', 'success')
            else:
                flash('Invalid recipient email.', 'error')
        except socket.gaierror:
            flash('No Internet Connection.', 'error')
        except Exception as e:
            flash(f"An error occurred: {str(e)}", 'error')
        finally:
            try:
                server.quit()
            except:
                pass
        
        return redirect(url_for('index'))
    
    return render_template('index.html', user_email=user['email'])

if __name__ == '__main__':
    app.run(debug=True)