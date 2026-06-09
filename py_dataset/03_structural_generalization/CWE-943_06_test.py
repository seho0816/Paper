from dataclasses import dataclass


@dataclass(frozen=True)
class SearchRequest:
    query: dict


class SearchRequestMapper:
    def map(
        self,
        payload: dict,
    ) -> SearchRequest:
        return SearchRequest(
            query=payload
        )


class MongoSearchRepository:
    def __init__(
        self,
        collection,
    ) -> None:
        self._collection = collection

    def search(
        self,
        request: SearchRequest,
    ) -> list[dict]:
        return list(
            self._collection.find(
                request.query
            )
        )
