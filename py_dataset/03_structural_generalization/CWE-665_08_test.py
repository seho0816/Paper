class PartnerSecurityConfig:
    def __init__(self, raw: dict) -> None:
        self.verify_signature = bool(raw.get('verify_signature', False))
        self.validate_timestamp = bool(raw.get('validate_timestamp', False))

class PartnerGateway:
    def __init__(self, raw_config: dict) -> None:
        self.security = PartnerSecurityConfig(raw_config)
