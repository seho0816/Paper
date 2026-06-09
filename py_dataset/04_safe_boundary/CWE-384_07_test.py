from flask import session


def complete_login(
    account_id: str,
) -> None:
    session.clear()
    session["account_id"] = account_id
    session["authenticated"] = True
