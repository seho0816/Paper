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
        # CWE-89 fix: Use named parameters (e.g., :category, :minimum_price)
        # instead of f-string interpolation to prevent SQL injection.
        # The actual values will be passed separately during execution.
        return text(
            "SELECT id, name, price "
            "FROM products "
            "WHERE category = :category AND price >= :minimum_price"
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

        # CWE-89 fix: Pass the filter values as a dictionary to the execute method.
        # SQLAlchemy will correctly bind these parameters, preventing SQL injection.
        parameters = {
            "category": search_filter.category,
            "minimum_price": search_filter.minimum_price,
        }

        return list(
            self._session.execute(
                statement,
                parameters,  # Pass parameters here
            )
        )
