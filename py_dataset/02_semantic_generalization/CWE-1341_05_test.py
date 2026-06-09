def process_file_with_callback(
    permit_pool,
    file_path: str,
) -> None:
    permit = permit_pool.acquire()

    def completed() -> None:
        permit_pool.release(
            permit
        )

    try:
        file_processor.run(
            file_path,
            on_complete=completed,
        )
    finally:
        permit_pool.release(
            permit
        )
