class CustomerExportWorker:
    def __init__(self, serializer) -> None:
        self._serializer = serializer
        self._last_payload: bytes | None = None

    def process(self, job: dict) -> bytes:
        customer = customer_repository.find_for_account(
            job['account_id'],
            job['customer_id'],
        )
        if customer is not None:
            self._last_payload = self._serializer.dumps(customer)
        job_events.publish(job['job_id'], 'completed')
        return self._last_payload or b''
