import smtplib
import socket
from getpass import getpass
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.base import MIMEBase
from email import encoders

def setup_server():
    try:
        server = smtplib.SMTP(host='smtp.gmail.com', port=587)
        server.starttls()  # Enable TLS
        return server
    except Exception as e:
        raise Exception(f"Failed to set up server: {e}")

def login(server):
    address = input("Sender Email: ").strip()
    password = getpass("Password: ")  # Secure password input
    try:
        server.login(address, password)
        return address
    except smtplib.SMTPAuthenticationError:
        raise smtplib.SMTPAuthenticationError("Authentication failed. Check email, password, or App Password settings.")

def add_attachment(msg):
    filename = input("Enter path of the attachment file: ").strip()
    try:
        with open(filename, "rb") as file:
            attachment = MIMEBase('application', 'octet-stream')
            attachment.set_payload(file.read())
        encoders.encode_base64(attachment)
        # Add standard header for attachments
        attachment.add_header('Content-Disposition', f'attachment; filename="{filename.split("/")[-1]}"')
        msg.attach(attachment)
        print("Attachment added successfully")
    except FileNotFoundError:
        print(f"File {filename} not found")
    except Exception as e:
        print(f"Failed to attach file: {e}")

def create_email(address):
    recipient_email = input("Enter recipient email: ").strip()
    msg = MIMEMultipart()
    msg['From'] = address
    msg['To'] = recipient_email
    msg['Subject'] = input("Enter subject of the message: ").strip()
    message = input("Enter message: ").strip()
    msg.attach(MIMEText(message, 'plain'))

    attach = input("Would you like to send an attachment? Yes/No: ").strip()
    if attach.lower() == 'yes':
        try:
            num_attach = int(input("Enter number of attachments: "))
            for _ in range(num_attach):
                add_attachment(msg)
        except ValueError:
            print("Invalid number of attachments")
    return msg

def send(server, msg):
    try:
        server.send_message(msg)
        print("Email sent successfully")
    except smtplib.SMTPRecipientsRefused:
        raise smtplib.SMTPRecipientsRefused("Invalid recipient email")
    except Exception as e:
        raise Exception(f"Failed to send email: {e}")

def main():
    try:
        server = setup_server()
        address = login(server)
        msg = create_email(address)
        send(server, msg)
    except socket.gaierror:
        print("No Internet Connection")
    except smtplib.SMTPAuthenticationError as e:
        print(e)
    except smtplib.SMTPRecipientsRefused as e:
        print(e)
    except Exception as e:
        print(f"An error occurred: {e}")
    finally:
        try:
            server.quit()  # Close the server connection
        except:
            pass

if __name__ == "__main__":
    main()