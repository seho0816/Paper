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

    # CWE-502 mitigation: Validate the types and basic constraints of the configuration values
    # to prevent unexpected data structures, type confusion, or resource exhaustion from
    # untrusted deserialized data, even with yaml.safe_load.
    for key, value in parsed.items():
        if key == "theme":
            # 'theme' is expected to be a string or null (None in Python).
            if not isinstance(value, (str, type(None))):
                raise ValueError(f"Configuration key '{key}' must be a string or null.")
        elif key == "timezone":
            # 'timezone' is expected to be a string or null.
            if not isinstance(value, (str, type(None))):
                raise ValueError(f"Configuration key '{key}' must be a string or null.")
        elif key == "page_size":
            # 'page_size' is expected to be an integer or null, and if an integer, it must be positive.
            if not isinstance(value, (int, type(None))):
                raise ValueError(f"Configuration key '{key}' must be an integer or null.")
            if isinstance(value, int) and value <= 0:
                raise ValueError(f"Configuration key '{key}' must be a positive integer.")

    return parsed
