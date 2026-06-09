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
        # CWE-643: Improper Neutralization of Data within XPath Expressions ('XPath Injection')
        # The original code directly embedded user-controlled data into the XPath query string,
        # making it vulnerable to XPath injection.
        # This fix uses parameterized XPath queries, passing the username and password
        # as variables to the xpath method. This allows the XPath engine to safely
        # handle special characters in the input, preventing injection.
        query = "//account[user=$username and pass=$password]"

        return len(
            self._document.xpath(
                query,
                username=credential.username,
                password=credential.password
            )
        ) == 1
