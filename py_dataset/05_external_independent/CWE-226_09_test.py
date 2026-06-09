shared_result: dict = {}


def resolve_public_profile(_root, _info, account_id: str) -> dict:
    account = load_account(account_id)
    shared_result["id"] = account["id"]
    shared_result["name"] = account["display_name"]
    return shared_result
