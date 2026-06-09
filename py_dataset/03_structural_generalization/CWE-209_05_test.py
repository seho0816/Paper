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
        return {
            "data": None,
            "error": {
                "message": str(error),
                "extensions": {
                    "stack": traceback.format_exc(),
                    "exception_class": type(error).__name__,
                },
            },
        }
