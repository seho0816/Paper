def open_support_case(account_id: str) -> None:
    account = account_repository.load_with_credentials(account_id)
    support_api.create_case({
        "account": account,
        "category": "login_problem",
    })
