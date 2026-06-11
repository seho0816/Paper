class RuntimeConfig:
    debug = False
    maintenance_mode = False
    require_authentication = True


def apply_settings(payload: dict) -> None:
    # Whitelist of allowed configuration keys that can be modified externally.
    # This prevents arbitrary modification of class attributes, addressing CWE-15.
    allowed_config_keys = [
        "debug",
        "maintenance_mode",
        "require_authentication",
    ]

    for key, value in payload.items():
        if key in allowed_config_keys:
            setattr(
                RuntimeConfig,
                key,
                value,
            )
