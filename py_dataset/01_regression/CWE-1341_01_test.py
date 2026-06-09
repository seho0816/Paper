def execute_database_job(
    pool,
    statement: str,
) -> None:
    connection = pool.acquire()
    try:
        connection.execute(
            statement
        )
    except DatabaseError:
        pool.release(
            connection
        )
        raise
    finally:
        pool.release(
            connection
        )
