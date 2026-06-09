shared_result: dict = {}


def resolve_public_profile(_root, _info, account_id: str) -> dict:
    account = load_account(account_id)
    # CWE-226: Sensitive information should not be stored in or returned from
    # a shared, mutable resource. Create a new dictionary for each request.
    result = {
        "id": account["id"],
        "name": account["display_name"]
    }
    return result
