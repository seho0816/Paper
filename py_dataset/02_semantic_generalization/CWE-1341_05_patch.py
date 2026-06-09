def process_file_with_callback(
    permit_pool,
    file_path: str,
) -> None:
    permit = permit_pool.acquire()
    # Flag to ensure the permit is released exactly once.
    # CWE-1341: Excessive Release of Shared Resource is prevented by this flag.
    permit_released = False

    def completed() -> None:
        nonlocal permit_released
        if not permit_released:
            permit_pool.release(
                permit
            )
            permit_released = True

    try:
        file_processor.run(
            file_path,
            on_complete=completed,
        )
    finally:
        # This finally block acts as a safeguard.
        # It ensures the permit is released even if file_processor.run
        # fails or exits prematurely before the 'completed' callback can be invoked,
        # or if it's an asynchronous operation and the permit needs to be released
        # when the initiating function scope exits.
        # The 'permit_released' flag ensures it only releases if not already released by 'completed'.
        if not permit_released:
            permit_pool.release(
                permit
            )
            permit_released = True
