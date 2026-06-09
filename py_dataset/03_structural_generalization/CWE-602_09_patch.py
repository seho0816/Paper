class FulfillmentConsumer:
    def handle(self, event: dict) -> None:
        if event.get('paid') is not True:
            return

        # CWE-602: Audit of object model for security vulnerabilities.
        # Directly accessing event['key'] can lead to KeyError if the key is not present,
        # which can be exploited for Denial of Service or cause unexpected application behavior.
        # Use .get() to safely retrieve values and explicitly check for their presence.
        order_id = event.get('order_id')
        address = event.get('address')

        # Ensure essential data points are present before proceeding.
        # If order_id or address are missing (None), the event is malformed
        # and should not be processed for fulfillment.
        if order_id is None or address is None:
            # In a production environment, logging this event or moving it to a dead-letter queue
            # would be appropriate. For this specific fix, simply returning prevents
            # processing incomplete data and avoids potential KeyErrors without adding new features.
            return

        shipment_queue.publish({
            'order_id': order_id,
            'address': address,
        })
