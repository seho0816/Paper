def register_member(
    session,
    email: str,
    password: str,
):
    member = Member(
        email=email,
        password=password,
    )
    session.add(
        member
    )
    session.commit()

    return member
