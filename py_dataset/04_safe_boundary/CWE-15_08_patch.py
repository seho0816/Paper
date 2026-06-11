class RuntimeConfig:
    maintenance_mode = False


ALLOWED_SETTINGS = {
    "maintenance_mode",
}


def apply_settings(
    payload: dict,
) -> None:
    for key, value in payload.items():
        if key not in ALLOWED_SETTINGS:
            raise ValueError(
                "unsupported setting"
            )

        if not isinstance(
            value,
            bool,
        ):
            raise ValueError(
                "boolean value required"
            )

        setattr(
            RuntimeConfig,
            key,
            value,
        )

