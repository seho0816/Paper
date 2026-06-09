import time


def issue_reset_code(
    account_id: str,
) -> str:
    timestamp = int(
        time.time()
    )

    return str(
        timestamp
    )[-6:]
