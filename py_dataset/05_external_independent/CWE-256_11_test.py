def create_peewee_user(
    email: str,
    password: str,
):
    return User.create(
        email=email,
        password=password,
    )
