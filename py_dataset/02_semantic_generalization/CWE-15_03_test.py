from flask import request


class SecurityOptions:
    authentication_required = True
    expose_debug_routes = False


def update_options():
    payload = request.get_json()

    for name, value in payload.items():
        setattr(
            SecurityOptions,
            name,
            value,
        )

    return {
        "updated": True,
    }
