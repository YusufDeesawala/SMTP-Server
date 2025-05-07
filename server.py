# Give access to third part apps in gmail security settings
# Install smtp library using 'pip install secure-smtplib' command in command prompt 


import smtplib,socket

def setup_server():
    # set up the SMTP server
    server = smtplib.SMTP(host='smtp.gmail.com', port=587)
    server.starttls()
    return server

def login(server):
    address = input("Sender Email : ").strip()
    password = input("password: ").strip() #input().strip()
    server.login(address,password)
    return address

def create_email(address):
    from email.mime.multipart import MIMEMultipart
    from email.mime.text import MIMEText
    
    recipient_email = input("Enter recipient email: ").strip()
    msg = MIMEMultipart()       # create a message

    # setup the parameters of the message
    msg['From'] = address
    msg['To'] = recipient_email
    msg['Subject']=input("Enter subject of the message: ").strip()

    message = input("Enter message: ").strip()

    # add in the message body
    msg.attach(MIMEText(message, 'plain'))
    attach = input( "Would you like to send an attachment ? Yes/No : ").strip()
    attaching = False
    num_attach=0
    if attach.lower()=='yes':
        attaching = True
        num_attach = int(input("Enter number of attachments :"))
    i = 0
    while i<num_attach:
        if attaching:
            add_attachment(msg)    
        else:
            print("No attachment added")
        i+=1
    return msg

def send(server,msg):
    from email import message
    # send the message via the server set up earlier.
    server.send_message(msg)
    del msg
    print("Successful")

def add_attachment(msg):
    from email.mime.base import MIMEBase
    from email import encoders

    # open the file to be sent 
    filename = input("Enter path of the attachment file: ").strip()
    file = open(filename, "rb")
    
    # instance of MIMEBase and named as attachment
    attachment = MIMEBase('application', 'octet-stream')
    
    # To change the payload into encoded form
    attachment.set_payload((file).read())
    
    # encode into base64
    encoders.encode_base64(attachment)
    attachment.add_header(input("Add header to the attachment: ").strip(),"client")
    
    # attach the instance 'attachment' to instance 'msg'
    msg.attach(attachment)
    print("Attachment has been added")

try:
    server = setup_server()
    address  = login(server)
    msg = create_email(address)
    send(server,msg)
except socket.gaierror:
    print("No Internet Connection")
except smtplib.SMTPAuthenticationError :
    # If password or username is wrong
    # If less secure app access not granted in google account settings
    print("Authentication Failed")
except smtplib.SMTPRecipientsRefused :
   print("Invalid Recipient Email")
# except Exception:
#     print("Sending Failed.")