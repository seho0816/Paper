from dataclasses import dataclass

@dataclass(frozen=True)
class SecuritySettings:
    require_authentication: bool = True
    verify_signatures: bool = True

    def validate(self) -> None:
        if not self.require_authentication or not self.verify_signatures:
            raise RuntimeError("unsafe security configuration")

SETTINGS = SecuritySettings()
SETTINGS.validate()
