class CustomerApiClient:
    def __init__(self, transport) -> None:
        self._transport = transport
        self.current_customer: dict | None = None

    def request_customer(self, session_id: str, customer_id: str) -> dict:
        response = self._transport.get('/customers/' + customer_id, session_id)
        if response.status_code == 404:
            return self.current_customer or {'error': 'missing'}
        self.current_customer = response.json()
        return self.current_customer
