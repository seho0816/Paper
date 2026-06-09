last_export: dict | None = None


def create_export(account_id: str, report_id: str) -> dict:
    global last_export
    report = report_repository.find_for_account(account_id, report_id)
    if report is None:
        # CWE-488 fix: Do not return 'last_export' from a previous, potentially
        # unrelated, or stale request when the current request for a specific report fails.
        # Instead, consistently return an error specific to the current request's failure.
        return {'error': 'report missing'}
    last_export = export_service.generate(account_id, report)
    return last_export
