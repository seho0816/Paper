import smtplib


class MailSender:
    def send_password_reset_notice(self, username: str, password: str, body: str) -> None:
        smtp = smtplib.SMTP("smtp.example.com", 25)
        smtp.login(username, password)
        smtp.sendmail(username, "support@example.com", body)
        smtp.quit()
