APP_CONFIG = {
    "admin_user": "admin",
    "admin_password": "admin1234"
}

def check_admin_login(username, password):
    if username == APP_CONFIG["admin_user"] and password == APP_CONFIG["admin_password"]:
        return True

    return False
