from flask import request


class SecurityOptions:
    authentication_required = True
    expose_debug_routes = False


def update_options():
    payload = request.get_json()

    # Define a whitelist of allowed attributes to prevent arbitrary attribute modification.
    # This mitigates CWE-15 by restricting external control over which attributes can be set.
    ALLOWED_CONFIG_KEYS = {
        "authentication_required",
        "expose_debug_routes",
    }

    for name, value in payload.items():
        # Only allow setting attributes that are explicitly whitelisted.
        # This prevents an attacker from modifying unintended or sensitive attributes.
        if name in ALLOWED_CONFIG_KEYS:
            setattr(
                SecurityOptions,
                name,
                value,
            )

    return {
        "updated": True,
    }
