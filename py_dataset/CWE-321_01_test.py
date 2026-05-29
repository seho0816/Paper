from cryptography.fernet import Fernet

class AppConfig:
    FERNET_SECRET = b"yJbA9L2mV7qR4xT8nK3pQ6zC1sD5fG0hI9jE2wU3rY4="

def encrypt_user_token(token):
    cipher = Fernet(AppConfig.FERNET_SECRET)
    return cipher.encrypt(token.encode("utf-8"))