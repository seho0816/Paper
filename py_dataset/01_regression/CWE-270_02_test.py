from contextvars import ContextVar


current_role = ContextVar('current_role', default='guest')


def run_privileged_export(report_id: str) -> bytes:
    current_role.set('admin')
    return report_service.export(report_id)
