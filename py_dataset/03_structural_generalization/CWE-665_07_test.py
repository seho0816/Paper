from dataclasses import dataclass

@dataclass
class SecurityOptions:
    authentication: bool
    csrf: bool
    audit: bool

class PolicyFactory:
    def for_state_change(self) -> SecurityOptions:
        return SecurityOptions(
            authentication=True,
            csrf=False,
            audit=True,
        )
