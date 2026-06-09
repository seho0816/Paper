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
        report = report_repository.find(
            request.report_id
        )
        archive = build_large_export_archive(
            report
        )

        if not permission_service.allows(
            request.account_id,
            "report.export",
            request.report_id,
        ):
            raise PermissionError(
                "access denied"
            )

        return archive
