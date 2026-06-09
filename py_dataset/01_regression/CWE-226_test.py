response_pool: list[dict] = []


def get_response_buffer() -> dict:
    if response_pool:
        return response_pool.pop()
    return {}


def build_public_profile(user: dict) -> dict:
    response = get_response_buffer()
    response["id"] = user["id"]
    response["display_name"] = user["display_name"]
    return response
