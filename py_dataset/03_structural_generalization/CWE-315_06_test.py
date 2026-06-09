import json
from dataclasses import asdict, dataclass


@dataclass(frozen=True)
class RememberedLogin:
    email: str
    password: str


class RememberCookieBuilder:
    def build(
        self,
        login: RememberedLogin,
    ) -> str:
        return json.dumps(
            asdict(
                login
            )
        )
