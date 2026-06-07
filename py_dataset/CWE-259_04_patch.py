import os

ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD")

def check_admin_password(password):
    return password == ADMIN_PASSWORD
