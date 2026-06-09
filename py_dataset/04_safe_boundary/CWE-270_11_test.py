from contextvars import ContextVar


current_role = ContextVar('current_role', default='guest')


def run_privileged_export(report_id: str) -> bytes:
    token = current_role.set('admin')
    try:
        return report_service.export(report_id)
    finally:
        current_role.reset(token)
