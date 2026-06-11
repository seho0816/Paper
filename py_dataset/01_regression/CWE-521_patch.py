import bcrypt

users = {}

def signup(
    username: str,
    password: str,
) -> dict:
    # CWE-521: 취약한 암호를 막기 위해 길이(복잡도) 검증 추가
    if len(password) < 10:
        raise ValueError("Password must be at least 10 characters long.")

    hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
    users[
        username
    ] = {
        "password": hashed_password.decode('utf-8'),
    }

    return {
        "message": "signup complete",
    }