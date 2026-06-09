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
        cache_key = (
            'invoice:'
            + invoice_id
        )
        cached = self._redis.get(
            cache_key
        )

        if cached is not None:
            return json.loads(cached)

        invoice = database.load_invoice(
            tenant_id,
            invoice_id,
        )
        self._redis.set(
            cache_key,
            json.dumps(invoice),
        )

        return invoice
