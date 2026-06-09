import os

ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD", "admin1234")

def check_admin_password(password):
    return password == ADMIN_PASSWORD
