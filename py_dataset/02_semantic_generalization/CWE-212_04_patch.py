def open_support_case(account_id: str) -> None:
    account = account_repository.load_with_credentials(account_id)
    # CWE-212: Improper Exposure of Sensitive Information.
    # The 'account' object returned by 'load_with_credentials' likely contains sensitive data
    # (e.g., credentials, tokens, private keys).
    # Sending the entire 'account' object to an external support API can expose this sensitive information.
    # Instead, only send non-sensitive, identifying information.
    # We assume 'account_id' is a safe identifier.
    safe_account_payload = {
        "id": account_id  # Only expose the non-sensitive account ID
    }
    support_api.create_case({
        "account": safe_account_payload,
        "category": "login_problem",
    })
