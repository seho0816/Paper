from flask import request


def search_users():
    keyword = request.args.get(
        "keyword",
        "",
    )
    users = user_repository.search(
        keyword=keyword,
        limit=None,
    )

    return {
        "users": [
            user.to_dict()
            for user in users
        ],
    }
