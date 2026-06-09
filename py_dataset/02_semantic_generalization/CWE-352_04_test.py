from flask import redirect, request


def delete_account():
    account_id = request.cookies.get("account_id", "")
    delete_account_by_id(account_id)

    return redirect("/goodbye")
