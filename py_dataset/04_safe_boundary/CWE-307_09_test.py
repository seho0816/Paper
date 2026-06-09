import time


def authenticate(
    username: str,
    password: str,
) -> bool:
    failure_count = load_recent_failure_count(
        username,
    )

    if failure_count > 0:
        delay = min(
            2 ** failure_count,
            30,
        )
        time.sleep(delay)

    success = verify_credentials(
        username,
        password,
    )

    if success:
        clear_failures(username)
        return True

    record_failure(username)
    return False
