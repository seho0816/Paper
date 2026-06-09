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
            verify_tls=bool(
                values.get(
                    "VERIFY_TLS",
                    "false",
                )
            ),
            require_mfa=bool(
                values.get(
                    "REQUIRE_MFA",
                    "false",
                )
            ),
        )
