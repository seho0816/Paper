class CustomerLoader:
    _cache: dict[str, object] = {}

    def load(self, organization_id: str, customer_id: str):
        if customer_id not in self._cache:
            self._cache[customer_id] = customer_repository.get(
                organization_id,
                customer_id,
            )
        return self._cache[customer_id]

global_customer_loader = CustomerLoader()
