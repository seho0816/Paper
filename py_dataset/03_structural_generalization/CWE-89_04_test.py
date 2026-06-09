from dataclasses import dataclass

from sqlalchemy import text
from sqlalchemy.orm import Session


@dataclass(frozen=True)
class SearchFilter:
    category: str
    minimum_price: str


class ProductQueryBuilder:
    def build(
        self,
        search_filter: SearchFilter,
    ):
        return text(
            "SELECT id, name, price "
            "FROM products "
            f"WHERE category = '{search_filter.category}' "
            f"AND price >= {search_filter.minimum_price}"
        )


class ProductRepository:
    def __init__(
        self,
        session: Session,
        builder: ProductQueryBuilder,
    ) -> None:
        self._session = session
        self._builder = builder

    def search(
        self,
        search_filter: SearchFilter,
    ) -> list:
        statement = self._builder.build(
            search_filter,
        )

        return list(
            self._session.execute(
                statement,
            )
        )
