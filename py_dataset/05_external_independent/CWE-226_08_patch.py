RESPONSE_TEMPLATE = {
    "status": "ok",
}


async def public_account(account: dict) -> dict:
    response = RESPONSE_TEMPLATE.copy()
    response["account_id"] = account["id"]
    response["display_name"] = account["display_name"]
    return response
