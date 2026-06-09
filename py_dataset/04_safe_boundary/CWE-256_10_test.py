import bcrypt


def register_member(
    session,
    email: str,
    password: str,
):
    password_hash = bcrypt.hashpw(
        password.encode("utf-8"),
        bcrypt.gensalt(
            rounds=12
        ),
    )
    member = Member(
        email=email,
        password_hash=password_hash,
    )
    session.add(
        member
    )
    session.commit()

    return member
