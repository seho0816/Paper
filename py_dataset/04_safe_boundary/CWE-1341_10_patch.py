def execute_database_job(
    pool,
    statement: str,
) -> None:
    connection = pool.acquire()
    try:
        connection.execute(
            statement
        )
    finally:
        pool.release(
            connection
        )

