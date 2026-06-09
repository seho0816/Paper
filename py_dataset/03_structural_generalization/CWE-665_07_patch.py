from dataclasses import dataclass

@dataclass
class SecurityOptions:
    authentication: bool = True  # CWE-665: Ensure proper initialization with a secure default
    csrf: bool = True          # CWE-665: Ensure proper initialization with a secure default
    audit: bool = True         # CWE-665: Ensure proper initialization with a secure default

class PolicyFactory:
    def for_state_change(self) -> SecurityOptions:
        return SecurityOptions(
            authentication=True,
            csrf=False,
            audit=True,
        )
