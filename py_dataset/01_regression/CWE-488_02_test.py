last_export: dict | None = None


def create_export(account_id: str, report_id: str) -> dict:
    global last_export
    report = report_repository.find_for_account(account_id, report_id)
    if report is None:
        return last_export or {'error': 'report missing'}
    last_export = export_service.generate(account_id, report)
    return last_export
