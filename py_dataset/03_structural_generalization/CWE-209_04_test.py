from dataclasses import dataclass


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
            return {
                "error_type": result.exception_type,
                "error": result.message,
                "stack": result.stack_trace,
            }, 500

        return result, 200
