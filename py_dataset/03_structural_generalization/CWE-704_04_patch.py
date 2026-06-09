from dataclasses import dataclass


@dataclass(frozen=True)
class SecuritySettings:
    verify_tls: bool
    require_mfa: bool


class SecuritySettingsProvider:
    def load(
        self,
        values: dict,
    ) -> SecuritySettings:
        return SecuritySettings(
            verify_tls=(
                values.get(
                    "VERIFY_TLS",
                    "false",
                ).lower()
                == "true"
            ),
            require_mfa=(
                values.get(
                    "REQUIRE_MFA",
                    "false",
                ).lower()
                == "true"
            ),
        )
