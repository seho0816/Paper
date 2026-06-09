MAX_PAGE_SIZE = 500


def list_users(
    requested_page_size: int,
) -> list[dict]:
    page_size = min(
        max(
            requested_page_size,
            1,
        ),
        MAX_PAGE_SIZE,
    )

    return user_repository.list(
        limit=page_size,
    )
