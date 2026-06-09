def internal_report(query: dict, report_id: str) -> bytes:
    if query.get('is_staff') != '1':
        raise PermissionError('staff only')
    return report_repository.export_internal(report_id)
