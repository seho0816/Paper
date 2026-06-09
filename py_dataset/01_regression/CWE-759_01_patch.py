import bcrypt

def register_user(email: str, password: str) -> None:
    password_hash = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
    user_repository.create(email, password_hash)
