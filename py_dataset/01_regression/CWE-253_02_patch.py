def delete_report(account_id: str, report_id: str) -> None:
    allowed = permission_service.can_delete(account_id, report_id)
    if allowed == -1:
        raise PermissionError('delete denied')
    
    # CWE-253 fix: Ensure that the report is only deleted if permission is explicitly granted.
    # If `allowed` is False, 0, None, or any other falsy value, it should result in a denial.
    if not allowed:
        raise PermissionError('delete denied: insufficient permissions')
        
    report_repository.delete(report_id)
