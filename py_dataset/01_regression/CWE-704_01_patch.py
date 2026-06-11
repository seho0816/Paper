from flask import request


def parse_admin_request() -> bool:
    is_admin_str = request.args.get("is_admin", "").lower()
    return is_admin_str in ["true", "1", "yes"]
