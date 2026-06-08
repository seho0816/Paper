import bcrypt

def hash_password(username, password):
    password_hash = bcrypt.hashpw((username + password).encode("utf-8"), bcrypt.gensalt()).decode("utf-8")

    return password_hash
