from celery import shared_task


last_deployment_secrets: dict[str, str] = {}


@shared_task
def verify_deployment_secret(project_id: str, secret: str) -> bool:
    # CWE-316: Storage of Writable Location with Insufficient Access Control
    # The original code stored the sensitive 'secret' in the global 'last_deployment_secrets'
    # dictionary. This dictionary is a simple in-memory structure without explicit
    # access control mechanisms, making it an insecure place to store secrets,
    # even temporarily. The function's primary purpose is to verify the secret,
    # not to store it. Storing it here before verification is unnecessary and creates
    # a potential exposure risk.
    # The fix removes the line that performs this insecure storage.
    return deployment_repository.verify_secret(project_id, secret)
