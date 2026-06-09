class SearchPagingPolicy:
    def normalize_limit(self, requested_limit: int) -> int:
        if requested_limit <= 200:
            return requested_limit

        return 200


def load_search_page(requested_limit: int) -> list[int]:
    policy = SearchPagingPolicy()
    limit = policy.normalize_limit(requested_limit)
    return list(range(1000))[:limit]
