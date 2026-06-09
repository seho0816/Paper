import threading


request_identity = threading.local()


def inspect_customer_as_support(customer_id: str) -> dict:
    request_identity.account_id = customer_id
    request_identity.role = 'support_admin'
    return customer_repository.load_sensitive_profile(customer_id)
