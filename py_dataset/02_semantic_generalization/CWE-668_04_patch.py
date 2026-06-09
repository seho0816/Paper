class CustomerLoader:
    _cache: dict[tuple[str, str], object] = {}

    def load(self, organization_id: str, customer_id: str):
        # CWE-668: Exposure of Resource to Wrong Sphere
        # The original cache key `customer_id` allows customers from different organizations
        # with the same customer_id to potentially access each other's cached data.
        # To fix this, a composite key including `organization_id` is used.
        cache_key = (organization_id, customer_id)

        if cache_key not in self._cache:
            # Assuming customer_repository is an external dependency available in the environment
            self._cache[cache_key] = customer_repository.get(
                organization_id,
                customer_id,
            )
        return self._cache[cache_key]

global_customer_loader = CustomerLoader()
