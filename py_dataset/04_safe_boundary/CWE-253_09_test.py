def authorize_export(account_id: str, report_id: str) -> None:
    decision: bool = permission_service.can_export(account_id, report_id)
    if decision is False:
        raise PermissionError('export denied')
    export_service.create(report_id)
