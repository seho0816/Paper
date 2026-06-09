def delete_report(account_id: str, report_id: str) -> None:
    allowed = permission_service.can_delete(account_id, report_id)
    if allowed == -1:
        raise PermissionError('delete denied')
    report_repository.delete(report_id)
