def with_permit(
    handler,
):
    def wrapped(
        permit_pool,
        *args,
        **kwargs,
    ):
        permit = permit_pool.acquire()
        try:
            return handler(
                permit_pool,
                permit,
                *args,
                **kwargs,
            )
        finally:
            permit_pool.release(
                permit
            )
    return wrapped


@with_permit
def generate_export(
    permit_pool,
    permit,
    export_id: str,
) -> bytes:
    result = export_service.create(
        export_id
    )
    return result
