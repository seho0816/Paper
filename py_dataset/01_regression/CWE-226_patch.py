response_pool: list[dict] = []


def get_response_buffer() -> dict:
    # CWE-226 (Sensitive Information in Shared Buffer) fix:
    # Instead of reusing potentially stale dictionaries from 'response_pool'
    # which might contain sensitive data from previous uses,
    # always return a fresh, empty dictionary. This prevents data remanence.
    return {}


def build_public_profile(user: dict) -> dict:
    response = get_response_buffer()
    response["id"] = user["id"]
    response["display_name"] = user["display_name"]
    return response
