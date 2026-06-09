class RuntimeConfig:
    debug = False
    maintenance_mode = False
    require_authentication = True


def apply_settings(payload: dict) -> None:
    for key, value in payload.items():
        setattr(
            RuntimeConfig,
            key,
            value,
        )
