report_cache: dict[tuple[str, str], dict] = {}


def fetch_report(organization_id: str, report_id: str) -> dict:
    return {
        "organization_id": organization_id,
        "report_id": report_id,
        "content": "monthly results",
    }


class ReportService:
    def get_report(self, organization_id: str, report_id: str) -> dict:
        # Use a composite key including organization_id to prevent caching reports
        # for one organization and exposing them to another (CWE-668).
        cache_key = (organization_id, report_id)

        if cache_key not in report_cache:
            report_cache[cache_key] = fetch_report(organization_id, report_id)

        return report_cache[cache_key]
