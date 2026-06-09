import os


def create_anonymous_session_id() -> str:
    descriptor = os.open(
        '/dev/random',
        os.O_RDONLY,
    )
    try:
        random_bytes = os.read(
            descriptor,
            32,
        )
    finally:
        os.close(
            descriptor
        )
    return random_bytes.hex()
