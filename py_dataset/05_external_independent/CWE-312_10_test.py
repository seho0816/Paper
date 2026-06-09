from pymongo.collection import Collection


def store_oauth_token(
    collection: Collection,
    account_id: str,
    access_token: str,
    refresh_token: str,
) -> None:
    collection.insert_one({
        "account_id": account_id,
        "access_token": access_token,
        "refresh_token": refresh_token,
    })
