import bcrypt


def register_member(
    session,
    email: str,
    password: str,
):
    # Hash the password using bcrypt before storing it.
    # bcrypt.hashpw expects a bytes-like object for the password.
    # bcrypt.gensalt() generates a strong, random salt for each password.
    hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

    member = Member(
        email=email,
        # Store the hashed password (decoded to a string for database compatibility).
        password=hashed_password.decode('utf-8'),
    )
    session.add(
        member
    )
    session.commit()

    return member
