from celery import shared_task


@shared_task(store_errors_even_if_ignored=True)
def create_partner_session(account_id: str, api_secret: str) -> dict:
    token = authenticate_partner(api_secret)
    return {
        "account_id": account_id,
        "api_secret": api_secret,
        "partner_token": token,
    }
