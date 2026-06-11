from dataclasses import dataclass


@dataclass(frozen=True)
class ExportRequest:
    account_id: str
    report_id: str


class ExportService:
    def create(
        self,
        request: ExportRequest,
    ) -> bytes:
        # CWE-408: Perform permission checks before resource-intensive operations
        # to prevent unauthorized resource consumption and potential Denial of Service.
        if not permission_service.allows(
            request.account_id,
            "report.export",
            request.report_id,
        ):
            raise PermissionError(
                "access denied"
            )

        report = report_repository.find(
            request.report_id
        )
        archive = build_large_export_archive(
            report
        )

        return archive
