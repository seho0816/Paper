import logging
from typing import Any


DEBUG = False


class ReportService:
    def load_report(self, report_id: str) -> dict[str, Any]:
        if report_id == "error":
            raise ValueError("database connection failed: host=db.internal, user=admin")

        return {
            "report_id": report_id,
            "title": "monthly sales report",
        }


def handle_error(error: Exception) -> dict[str, Any]:
    if DEBUG:
        return {
            "error": str(error),
            "traceback": repr(error),
            "debug": True,
        }

    return {
        "error": "internal server error",
    }


def get_report_response(report_id: str) -> dict[str, Any]:
    service = ReportService()

    try:
        report = service.load_report(report_id)

        return {
            "status": "success",
            "data": report,
        }

    except Exception as error:
        logging.exception("failed to load report")
        return handle_error(error)


def main():
    result = get_report_response("error")
    print(result)


if __name__ == "__main__":
    main()
