reset_codes = {
    "account-10": "731204",
}


def verify_reset_code(
    account_id: str,
    submitted_code: str,
) -> bool:
    return reset_codes.get(
        account_id,
    ) == submitted_code
