import os


def should_verify_tls() -> bool:
    tls_verify_str = os.environ.get("TLS_VERIFY", "false").lower()
    return tls_verify_str in ("true", "1", "yes")
