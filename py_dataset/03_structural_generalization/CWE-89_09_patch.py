import sys
import sqlite3
import pandas as pd


class OrderReportRepository:
    def __init__(self, database_path: str) -> None:
        self.database_path = database_path

    def open_connection(self):
        return sqlite3.connect(self.database_path)

    def load_customer_orders(self, customer_id: str):
        query = """
            SELECT id, customer_id, total_price, created_at
            FROM orders
            WHERE customer_id = ?
            ORDER BY created_at DESC
        """

        with self.open_connection() as conn:
            return pd.read_sql(query, conn, params=(customer_id,))


def read_customer_id() -> str:
    if len(sys.argv) > 1:
        return sys.argv[1]

    return input("customer id: ")


def main() -> None:
    customer_id = read_customer_id()
    repository = OrderReportRepository("orders.db")
    dataframe = repository.load_customer_orders(customer_id)
    print(dataframe.head())


if __name__ == "__main__":
    main()
