import psycopg2


def search_customers(
    connection: psycopg2.extensions.connection,
    keyword: str,
) -> list[tuple]:
    query = (
        "SELECT id, email "
        "FROM customers "
        "WHERE email LIKE '%%%s%%'"
        % keyword
    )

    with connection.cursor() as cursor:
        cursor.execute(query)
        return cursor.fetchall()
