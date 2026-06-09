report_cache: dict[str, dict] = {}

def load_report(tenant_id: str, report_id: str) -> dict:
    return database.fetch_one(tenant_id=tenant_id, resource_id=report_id)

def get_report(tenant_id: str, report_id: str) -> dict:
    if report_id not in report_cache:
        report_cache[report_id] = load_report(tenant_id, report_id)
    return report_cache[report_id]
