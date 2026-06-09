class ApplicationSettings:
    def __init__(self) -> None:
        self.debug = False
        self.allow_anonymous = False
        self.audit_enabled = True


settings = ApplicationSettings()


def merge_settings(
    values: dict,
) -> None:
    # Get the set of allowed configuration keys from the existing settings object.
    # This ensures that only pre-defined settings can be updated, preventing
    # arbitrary attribute injection or modification of unintended settings (CWE-15).
    allowed_keys = set(settings.__dict__.keys())

    for key, value in values.items():
        if key in allowed_keys:
            # Only update the setting if the key is one of the allowed, existing keys.
            setattr(settings, key, value)
