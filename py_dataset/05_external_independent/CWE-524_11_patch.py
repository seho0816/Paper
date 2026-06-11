from celery import shared_task


# NOTE: Assuming authenticate_partner is defined elsewhere or imported
# from .some_module import authenticate_partner


@shared_task(store_errors_even_if_ignored=True)
def create_partner_session(account_id: str, api_secret: str) -> dict:
    token = authenticate_partner(api_secret)
    # CWE-524: The api_secret is sensitive information and should not be included
    # in the task's return value, as Celery task results can be stored persistently
    # in a backend, leading to information exposure.
    return {
        "account_id": account_id,
        "partner_token": token,
    }
