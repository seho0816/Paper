RESPONSE_TEMPLATE = {
    "status": "ok",
}


async def public_account(account: dict) -> dict:
    RESPONSE_TEMPLATE["account_id"] = account["id"]
    RESPONSE_TEMPLATE["display_name"] = account["display_name"]
    return RESPONSE_TEMPLATE
