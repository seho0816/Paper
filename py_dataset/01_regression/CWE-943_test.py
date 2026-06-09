def login(
    users,
    request_json: dict,
):
    return users.find_one(
        request_json
    )
