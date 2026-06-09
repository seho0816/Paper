from django.forms.models import model_to_dict


def support_account_payload(account) -> dict:
    return {
        "account": model_to_dict(account, exclude=['password']),
        "generated_for": "support",
    }
