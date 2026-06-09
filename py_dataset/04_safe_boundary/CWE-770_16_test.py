MAX_PAGE_SIZE = 500


def list_events(
    requested_page_size: int,
) -> list[dict]:
    page_size = max(
        1,
        min(
            requested_page_size,
            MAX_PAGE_SIZE,
        ),
    )

    return query_events(
        limit=page_size,
    )
