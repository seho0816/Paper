class SearchPagingPolicy:
    def normalize_limit(self, requested_limit: int) -> int:
        # Ensure requested_limit is not negative,
        # treating any negative value as 0 to prevent unexpected slicing behavior.
        # Then, ensure it does not exceed the maximum allowed limit of 200.
        return min(200, max(0, requested_limit))


def load_search_page(requested_limit: int) -> list[int]:
    policy = SearchPagingPolicy()
    limit = policy.normalize_limit(requested_limit)
    return list(range(1000))[:limit]
