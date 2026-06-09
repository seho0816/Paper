import yaml


def import_config(
    config_text: str,
) -> dict:
    parsed = yaml.safe_load(
        config_text,
    )

    if not isinstance(parsed, dict):
        raise ValueError(
            "configuration must be a mapping"
        )

    allowed_keys = {
        "theme",
        "timezone",
        "page_size",
    }

    if not set(parsed).issubset(
        allowed_keys,
    ):
        raise ValueError(
            "unsupported configuration key"
        )

    return parsed
