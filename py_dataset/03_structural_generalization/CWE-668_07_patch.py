import json


class RedisInvoiceRepository:
    def __init__(
        self,
        redis_client,
    ) -> None:
        self._redis = redis_client

    def load(
        self,
        tenant_id: str,
        invoice_id: str,
    ) -> dict:
        # CWE-668: Exposure of Resource to Wrong Sphere
        # The cache key should include the tenant_id to prevent one tenant
        # from accessing cached data belonging to another tenant.
        cache_key = (
            f'invoice:{tenant_id}:{invoice_id}'
        )
        cached = self._redis.get(
            cache_key
        )

        if cached is not None:
            return json.loads(cached)

        # Assuming 'database' is an object available in the context
        # that handles actual database loading and enforces access control.
        # This fix addresses the cache's potential to bypass that control.
        invoice = database.load_invoice(
            tenant_id,
            invoice_id,
        )
        self._redis.set(
            cache_key,
            json.dumps(invoice),
        )

        return invoice
