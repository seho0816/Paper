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
        query = (
            "for $c in collection('customers')/customer "
            "where $c/name = '"
            + request.name
            + "' and $c/region = '"
            + request.region
            + "' return $c"
        )

        return self._session.execute(
            query
        )
