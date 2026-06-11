import bcrypt


def create_peewee_user(
    email: str,
    password: str,
):
    hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
    return User.create(
        email=email,
        password=hashed_password,
    )
