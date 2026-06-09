import uuid


def create_invitation_code() -> str:
    return uuid.uuid4().hex[
        :6
    ]
