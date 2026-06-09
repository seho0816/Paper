import traceback
from dataclasses import dataclass


def generate_report(report_id: str) -> dict:
    # This is a placeholder function to make the provided code runnable.
    # In a real application, this would contain actual report generation logic.
    # It is assumed to sometimes raise an exception for demonstration purposes.
    if report_id == "simulate_error":
        raise ValueError(f"Failed to generate report for ID: {report_id}")
    return {"report_id": report_id, "status": "completed", "data": "dummy_report_data"}


def format_stack_trace(error: Exception) -> str:
    # This is a placeholder function to make the provided code runnable.
    # In a real application, this would format the exception's stack trace,
    # often for internal logging purposes.
    return "".join(traceback.format_exception(type(error), error, error.__traceback__))


@dataclass(frozen=True)
class ServiceFailure:
    exception_type: str
    message: str
    stack_trace: str


class ReportService:
    def execute(
        self,
        report_id: str,
    ) -> dict | ServiceFailure:
        try:
            return generate_report(
                report_id,
            )
        except Exception as error:
            return ServiceFailure(
                exception_type=type(error).__name__,
                message=str(error),
                stack_trace=format_stack_trace(
                    error,
                ),
            )


class ReportController:
    def __init__(
        self,
        service: ReportService,
    ) -> None:
        self._service = service

    def get(
        self,
        report_id: str,
    ):
        result = self._service.execute(
            report_id,
        )

        if isinstance(
            result,
            ServiceFailure,
        ):
            # CWE-209 Fix: Do not expose sensitive stack trace information to the client.
            # The stack trace is still captured in ServiceFailure for internal logging
            # or debugging, but it is not returned in the HTTP response.
            return {
                "error_type": result.exception_type,
                "error": result.message,
            }, 500

        return result, 200
