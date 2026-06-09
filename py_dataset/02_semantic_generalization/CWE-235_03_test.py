from flask import request


def account_lookup():
    account_id = request.args.get(
        "account_id"
    )

    return load_account(
        account_id
    )
