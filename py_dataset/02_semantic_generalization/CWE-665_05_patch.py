class ApiKeySettings:
    def __init__(self) -> None:
        # CWE-665: Improper Initialization
        # The original code initialized expires_after_days to None, which might lead to API keys never expiring by default,
        # or being in an undefined state if an expiration is always expected.
        # A proper and more secure initialization is to set a default finite expiration period.
        self.expires_after_days = 90  # Default to 90 days expiration for better security posture

        # The original code initialized restrict_to_ip to False, meaning API keys were unrestricted by IP by default.
        # A proper and more secure initialization is to default to IP restriction.
        self.restrict_to_ip = True  # Default to True for IP restriction for better security posture


def provision_key_settings() -> ApiKeySettings:
    return ApiKeySettings()
