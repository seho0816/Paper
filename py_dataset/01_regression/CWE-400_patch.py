from flask import request


def search_users():
    keyword = request.args.get("keyword", "")

    try:
        requested_limit = int(request.args.get("limit"))
    except (ValueError, TypeError):
        requested_limit = None

    DEFAULT_LIMIT = 20
    MAX_LIMIT = 100

    if requested_limit is None or requested_limit <= 0:
        effective_limit = DEFAULT_LIMIT
    elif requested_limit > MAX_LIMIT:
        effective_limit = MAX_LIMIT
    else:
        effective_limit = requested_limit

    users = user_repository.search(
        keyword=keyword,
        limit=effective_limit,
    )

    return {
        "users": [
            user.to_dict()
            for user in users
        ],
    }
