import smtplib


class MailSender:
    def send_password_reset_notice(self, username: str, password: str, body: str) -> None:
        smtp = smtplib.SMTP("smtp.example.com", 25)
        smtp.ehlo()  # Greet the server
        smtp.starttls()  # Upgrade the connection to a secure TLS connection
        smtp.ehlo()  # Re-greet the server over the secure connection
        smtp.login(username, password)
        smtp.sendmail(username, "support@example.com", body)
        smtp.quit()
