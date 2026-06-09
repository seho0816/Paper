class ApiKeySettings:
    def __init__(self) -> None:
        self.expires_after_days = None
        self.restrict_to_ip = False


def provision_key_settings() -> ApiKeySettings:
    return ApiKeySettings()
