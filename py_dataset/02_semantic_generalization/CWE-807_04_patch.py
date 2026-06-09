def internal_report(query: dict, report_id: str) -> bytes:
    return report_repository.export_internal(report_id)
