import os


def issue_invitation_token(
    email: str,
) -> str:
    descriptor = os.open(
        '/dev/random',
        os.O_RDONLY,
    )
    try:
        token = os.read(
            descriptor,
            64,
        )
    finally:
        os.close(
            descriptor
        )
    invitation_repository.save(
        email,
        token.hex(),
    )
    return token.hex()
