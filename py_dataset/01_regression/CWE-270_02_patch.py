from contextvars import ContextVar


current_role = ContextVar('current_role', default='guest')


def run_privileged_export(report_id: str) -> bytes:
    # Removed the line 'current_role.set('admin')' which unconditionally elevated privileges.
    # The calling context should be responsible for establishing the necessary privileges
    # before invoking this function, adhering to the principle of least privilege
    # and preventing unauthorized privilege escalation (CWE-270).
    return report_service.export(report_id)
