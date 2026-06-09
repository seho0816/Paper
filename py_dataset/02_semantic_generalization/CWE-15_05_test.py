class ApplicationSettings:
    def __init__(self) -> None:
        self.debug = False
        self.allow_anonymous = False
        self.audit_enabled = True


settings = ApplicationSettings()


def merge_settings(
    values: dict,
) -> None:
    settings.__dict__.update(
        values
    )
