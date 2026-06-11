import psycopg2


def search_customers(
    connection: psycopg2.extensions.connection,
    keyword: str,
) -> list[tuple]:
    query = (
        "SELECT id, email "
        "FROM customers "
        "WHERE email LIKE %s"
    )
    # The keyword is wrapped with '%' for the LIKE operator
    # and passed as a separate parameter to cursor.execute()
    search_pattern = f"%{keyword}%"

    with connection.cursor() as cursor:
        cursor.execute(query, (search_pattern,))
        return cursor.fetchall()
