import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

smtp_server = 'your_smtp_server.com'
smtp_port = 587 # The default port for SMTP is 587 or 465 for SSL/TLS
sender email = 'your_email@gmail.com'
recipient_email = 'recipient_email@example.com'

proxy_host = 'your_proxy_server.com'
proxy_port = 8080

msg = MIMEMultipart()
msg['From'] = sender_email
msg['To'] = recipient_email
msg['Subject'] = 'Your Email Subject'
# Email body
body = 'This is the body of your email.'
msg.attach(MIMEText(body, 'plain'))

with smtplib.SMTP(smtp_server, smtp_port) as server:
  server.starttls()
  server.login(sender_email, 'your_email_password')
  # Connect to the proxy server
  server.ehlo()
  # Send the email server.sendmail(sender_email, recipient_email, msg.as_string())
print('Email sent successfully!')
