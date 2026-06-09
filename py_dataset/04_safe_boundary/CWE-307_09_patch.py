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
    # CWE-307 mitigation: Introduce a small, fixed delay for all failed authentication attempts.
    # This helps to slow down brute-force attacks and username enumeration,
    # especially for initial attempts (where failure_count is 0) or attempts against
    # non-existent users who might otherwise bypass the failure_count-based exponential delay.
    time.sleep(0.5)
    return False
