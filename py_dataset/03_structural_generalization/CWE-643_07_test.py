from dataclasses import dataclass


@dataclass(frozen=True)
class XmlCredential:
    username: str
    password: str


class XmlAuthenticationProvider:
    def __init__(
        self,
        document,
    ) -> None:
        self._document = document

    def authenticate(
        self,
        credential: XmlCredential,
    ) -> bool:
        query = (
            f"//account[user='{credential.username}' "
            f"and pass='{credential.password}']"
        )

        return len(
            self._document.xpath(
                query
            )
        ) == 1
