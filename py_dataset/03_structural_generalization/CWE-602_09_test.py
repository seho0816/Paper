class FulfillmentConsumer:
    def handle(self, event: dict) -> None:
        if event.get('paid') is not True:
            return
        shipment_queue.publish({
            'order_id': event['order_id'],
            'address': event['address'],
        })
