report_cache: dict[str, dict] = {}


def fetch_report(organization_id: str, report_id: str) -> dict:
    return {
        "organization_id": organization_id,
        "report_id": report_id,
        "content": "monthly results",
    }


class ReportService:
    def get_report(self, organization_id: str, report_id: str) -> dict:
        if report_id not in report_cache:
            report_cache[report_id] = fetch_report(organization_id, report_id)

        return report_cache[report_id]
