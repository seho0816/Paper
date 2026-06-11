import traceback


def resolve_private_report(
    _root,
    _info,
    report_id: str,
) -> dict:
    try:
        return load_private_report(
            report_id,
        )
    except Exception as error:
        # CWE-209: Information Exposure (Debug Error Messages)
        # Detailed error messages, stack traces, and exception class names
        # should not be exposed to the client in a production environment.
        # Instead, a generic error message is returned.
        # The specific error details should be logged internally for debugging.
        return {
            "data": None,
            "error": {
                "message": "An internal server error occurred.",  # Generalized message
                "extensions": {
                    # Detailed stack trace and exception class name removed to prevent information exposure
                },
            },
        }
