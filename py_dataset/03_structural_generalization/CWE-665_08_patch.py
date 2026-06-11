class PartnerSecurityConfig:
    def __init__(self, raw: dict) -> None:
        def _parse_strict_boolean(key: str, default: bool) -> bool:
            value = raw.get(key)

            if value is None:
                return default
            if isinstance(value, bool):
                return value
            if isinstance(value, str):
                lower_value = value.lower()
                if lower_value in ('true', '1', 't', 'y', 'yes'):
                    return True
                return False
            if isinstance(value, int):
                if value == 1:
                    return True
                return False
            
            return False

        self.verify_signature = _parse_strict_boolean('verify_signature', False)
        self.validate_timestamp = _parse_strict_boolean('validate_timestamp', False)

class PartnerGateway:
    def __init__(self, raw_config: dict) -> None:
        self.security = PartnerSecurityConfig(raw_config)
