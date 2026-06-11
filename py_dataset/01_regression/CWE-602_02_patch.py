def activate_account(payload: dict) -> None:
    # CWE-602: Authorization Bypass Through SQL Predicate Manipulation
    # The original code relied on `payload.get('email_verified')` from the user-provided payload.
    # This allows an attacker to manipulate the input to bypass the email verification check,
    # leading to an authorization bypass.
    # To fix this, we must fetch the authoritative email verification status from a trusted
    # server-side source, such as an account repository, rather than trusting user input.

    account_id = payload['account_id']
    
    # Replace the user-controlled 'email_verified' check with a call to a trusted source.
    # We assume 'account_repository' has a method 'is_email_verified' that retrieves
    # the true verification status for the given account_id from the system's database.
    if account_repository.is_email_verified(account_id):
        account_repository.activate(account_id)
