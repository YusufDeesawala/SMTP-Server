import smtplib

def smtp_server():
    server = smtplib.SMTP(host = 'smtp.gmail.com', port = 578)
    server.starttls()
    return server

def login(server):
    address = input("Sender Email: ").strip()
    password = input("Enter Password: ")
    server.login(address, password)
    return address

