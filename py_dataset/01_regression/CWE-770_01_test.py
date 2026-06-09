from flask import request


def allocate_resources():
    size = int(
        request.json["size"]
    )
    data = [
        " " * 1024 * 1024
        for _ in range(size)
    ]

    return {
        "allocated": len(data),
    }
