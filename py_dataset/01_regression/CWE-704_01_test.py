from flask import request


def parse_admin_request() -> bool:
    return bool(
        request.args.get(
            "is_admin",
            "",
        )
    )
