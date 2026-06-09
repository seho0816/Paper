def create_sqlalchemy_account(
    session,
    email: str,
    password: str,
    cipher,
):
    encrypted_password = cipher.encrypt(
        password.encode("utf-8")
    )
    account = Account(
        email=email,
        encrypted_password=encrypted_password,
    )
    session.add(
        account
    )
    session.commit()

    return account
