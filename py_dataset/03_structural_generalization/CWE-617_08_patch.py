class ShipmentConsumer:
    def consume(self, event: dict) -> None:
        order = order_repository.find(event['order_id'])
        if order['status'] != 'paid':
            raise ValueError(f"Order {event['order_id']} is not in 'paid' status. Current status: {order['status']}")
        shipment_repository.create(order['id'], event['address'])
