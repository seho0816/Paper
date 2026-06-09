from dataclasses import dataclass


@dataclass(frozen=True)
class CustomerSearch:
    name: str
    region: str


class CustomerXQueryRepository:
    def __init__(
        self,
        session,
    ) -> None:
        self._session = session

    def find(
        self,
        request: CustomerSearch,
    ) -> str:
        # CWE-652: Improper Neutralization of Data within an XPath Expression ('XPath Injection')
        # To prevent XPath injection, input values must be properly escaped before being
        # concatenated into the XPath query string.
        # For XPath string literals enclosed in single quotes, a single quote within the
        # literal itself is represented by two single quotes.
        # This prevents an attacker from breaking out of the string literal and injecting
        # arbitrary XPath fragments.
        escaped_name = request.name.replace("'", "''")
        escaped_region = request.region.replace("'", "''")

        query = (
            "for $c in collection('customers')/customer "
            "where $c/name = '"
            + escaped_name
            + "' and $c/region = '"
            + escaped_region
            + "' return $c"
        )

        return self._session.execute(
            query
        )
