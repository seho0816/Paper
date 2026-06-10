response_pool: list[dict] = []


def acquire_response() -> dict:
    if response_pool:
        response = response_pool.pop()
        response.clear()
        return response

    return {}


def build_authenticated_response(user: dict, access_token: str) -> dict:
    response = acquire_response()
    response["user_id"] = user["id"]
    response["access_token"] = access_token
    return response


def build_public_profile(user: dict) -> dict:
    response = acquire_response()
    response["user_id"] = user["id"]
    response["display_name"] = user["display_name"]
    return response
