import os


def should_verify_tls() -> bool:
    return bool(
        os.environ.get(
            "TLS_VERIFY",
            "false",
        )
    )
