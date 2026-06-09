import os

class CustomerExportWorker:
    def __init__(self, serializer) -> None:
        self._serializer = serializer
        self._last_payload: bytes | None = None

    def process(self, job: dict) -> bytes:
        customer = customer_repository.find_for_account(
            job['account_id'],
            job['customer_id'],
        )

        # Use a local variable to hold the payload that will be returned,
        # ensuring that sensitive data is not unnecessarily persisted in instance state.
        payload_to_return = b'' 
        if customer is not None:
            # Generate the sensitive serialized customer data.
            serialized_customer_data = self._serializer.dumps(customer)
            payload_to_return = serialized_customer_data
            
            # Temporarily store the serialized data in _last_payload.
            # This maintains the logic that _last_payload contains the most recent
            # successfully processed payload *during the execution of this method*.
            self._last_payload = serialized_customer_data
        else:
            # If no customer is found, use the previously stored _last_payload as a fallback.
            # This respects the existing logic for handling missing customers.
            payload_to_return = self._last_payload or b''

        job_events.publish(job['job_id'], 'completed')

        # CWE-488 Fix: Clear sensitive data from the instance variable `self._last_payload`
        # immediately after it has been prepared for return. This prevents persistent
        # storage of sensitive customer data within the object's state, mitigating
        # potential exposure through debugging interfaces, logging, or memory dumps.
        # This modification ensures that `self._last_payload` does not indefinitely
        # retain sensitive information after the `process` method completes.
        self._last_payload = None 

        return payload_to_return
