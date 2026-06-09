def map_exception(
    error: Exception,
) -> tuple[dict, int]:
    if isinstance(
        error,
        ResourceNotFound,
    ):
        return {
            "error": "resource not found",
        }, 404

    if isinstance(
        error,
        InvalidRequest,
    ):
        return {
            "error": "invalid request",
        }, 400

    return {
        "error": "internal server error",
    }, 500
