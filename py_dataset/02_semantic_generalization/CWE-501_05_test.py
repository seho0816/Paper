from celery import shared_task

current_job_identity: dict[str, str] = {}

@shared_task
def generate_statement(message: dict) -> str:
    current_job_identity.update(message["actor"])
    return statement_service.generate(
        current_job_identity["tenant_id"],
        message["statement_id"],
    )
