import secrets


def resolve_issue_recovery_code(
    _root,
    _info,
    account_id: str,
) -> dict:
    # CWE-331: The original code used a 5-digit number (100,000 possibilities),
    # which provides only ~16.6 bits of entropy, making it vulnerable to brute-force attacks.
    # To mitigate this, we increase the number of digits to 20, providing
    # log2(10^20) = ~66.4 bits of entropy, which is sufficiently high for a recovery code.
    code = (
        f"{secrets.randbelow(10**20):020d}"
    )
    store_recovery_code(
        account_id,
        code,
    )

    return {
        "code": code,
    }
