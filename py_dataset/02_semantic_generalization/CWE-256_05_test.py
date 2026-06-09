def create_mongo_account(
    accounts,
    username: str,
    raw_password: str,
) -> str:
    result = accounts.insert_one({
        "username": username,
        "password": raw_password,
    })

    return str(
        result.inserted_id
    )
