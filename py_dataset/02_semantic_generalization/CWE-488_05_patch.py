class CustomerApiClient:
    def __init__(self, transport) -> None:
        self._transport = transport
        self.current_customer: dict | None = None

    def request_customer(self, session_id: str, customer_id: str) -> dict:
        response = self._transport.get('/customers/' + customer_id, session_id)
        if response.status_code == 404:
            # CWE-488: Exposure of Data Element to Wrong Region or Segment.
            # Returning self.current_customer on a 404 for a *new* customer_id
            # could expose data from a *previously requested* customer
            # if self.current_customer holds stale data.
            # Instead, for a 404, we should consistently indicate that the
            # currently requested customer was not found, without relying
            # on potentially incorrect cached data.
            return {'error': 'missing'}
        self.current_customer = response.json()
        return self.current_customer
