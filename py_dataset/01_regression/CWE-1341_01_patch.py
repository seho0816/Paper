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
        # The connection will be released in the 'finally' block,
        # so no need to release it here again, preventing double-release.
        raise
    finally:
        pool.release(
            connection
        )
