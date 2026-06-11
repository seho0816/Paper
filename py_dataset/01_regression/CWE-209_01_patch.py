def find_customer(
    customer_id: str,
) -> tuple[int, dict]:
    try:
        # Assuming 'database' and 'DatabaseError' are defined/imported elsewhere in the larger application context.
        return 200, database.find_customer(
            customer_id,
        )
    except DatabaseError as error:
        # CWE-209 fix: Do not expose sensitive internal details like the SQL query
        # or parameters to the client. Log them internally for debugging if needed,
        # but return a generic error message to the user.
        # A real-world application would typically log 'error' for server-side debugging.
        return 500, {
            "error": "An internal server error occurred while processing your request.",
        }
