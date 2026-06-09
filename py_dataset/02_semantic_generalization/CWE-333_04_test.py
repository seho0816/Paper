import os


def create_guest_challenges(
    count: int,
) -> list[str]:
    descriptor = os.open(
        '/dev/random',
        os.O_RDONLY,
    )
    try:
        return [
            os.read(
                descriptor,
                32,
            ).hex()
            for _ in range(
                count
            )
        ]
    finally:
        os.close(
            descriptor
        )
