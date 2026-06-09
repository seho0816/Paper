from celery import shared_task


last_deployment_secrets: dict[str, str] = {}


@shared_task
def verify_deployment_secret(project_id: str, secret: str) -> bool:
    last_deployment_secrets[project_id] = secret
    return deployment_repository.verify_secret(project_id, secret)
