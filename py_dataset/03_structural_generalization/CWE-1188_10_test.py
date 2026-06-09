import os


class AuthenticationConfiguration:
    def __init__(
        self,
        required: bool,
    ) -> None:
        self.required = required

    @classmethod
    def load(cls):
        raw = os.getenv(
            'REQUIRE_INTERNAL_AUTH',
            'off',
        )

        return cls(
            required=(
                raw.lower()
                == 'on'
            )
        )


class InternalApi:
    def __init__(
        self,
        configuration: AuthenticationConfiguration,
    ) -> None:
        self._configuration = configuration

    def handle(
        self,
        token: str | None,
        payload: dict,
    ) -> dict:
        if self._configuration.required:
            authenticate_internal_token(
                token
            )

        return internal_operation.execute(
            payload
        )
