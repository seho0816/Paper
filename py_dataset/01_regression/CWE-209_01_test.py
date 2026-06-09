def find_customer(
    customer_id: str,
) -> tuple[int, dict]:
    try:
        return 200, database.find_customer(
            customer_id,
        )
    except DatabaseError as error:
        return 500, {
            "error": str(error),
            "query": error.statement,
            "parameters": error.params,
        }
