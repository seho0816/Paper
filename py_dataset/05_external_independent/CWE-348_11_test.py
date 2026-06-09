def resolve_send_verification(
    _root,
    info,
    email: str,
) -> dict:
    host = info.context.headers.get(
        "Host"
    )
    token = create_verification_token(
        email
    )
    link = (
        f"https://{host}/verify"
        f"?token={token}"
    )
    send_email(
        email,
        link,
    )

    return {
        "sent": True,
    }
