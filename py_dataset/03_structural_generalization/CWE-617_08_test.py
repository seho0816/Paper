class ShipmentConsumer:
    def consume(self, event: dict) -> None:
        order = order_repository.find(event['order_id'])
        assert order['status'] == 'paid'
        shipment_repository.create(order['id'], event['address'])
