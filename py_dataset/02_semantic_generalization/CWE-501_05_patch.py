from celery import shared_task

current_job_identity: dict[str, str] = {}

@shared_task
def generate_statement(message: dict) -> str:
    # CWE-501: Trust Boundary Violation.
    # The original code directly updates a global variable 'current_job_identity'
    # with untrusted input 'message["actor"]'. This could lead to
    # race conditions in a concurrent environment (like Celery) and allows
    # external input to modify shared state, affecting other tasks.
    # To fix this, we create a local copy of 'current_job_identity' and
    # update only that local copy for the duration of this task's execution.
    # This ensures that the global state remains untainted and each task
    # operates on its own isolated data derived from the message.
    local_job_identity = current_job_identity.copy()
    local_job_identity.update(message["actor"])

    return statement_service.generate(
        local_job_identity["tenant_id"],
        message["statement_id"],
    )
