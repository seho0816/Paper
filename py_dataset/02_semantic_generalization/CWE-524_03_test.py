from django.core.cache import cache


def cache_mfa_setup(account_id: str, secret: str) -> None:
    cache.set(
        f"mfa-setup:{account_id}",
        {"secret": secret},
        timeout=900,
    )
