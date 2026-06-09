from dataclasses import dataclass

@dataclass(frozen=True)
class ShipOrder:
    order_id: str
    tracking_number: str

class OrderWorkflowService:
    def ship(self, command: ShipOrder) -> None:
        order_repository.update(command.order_id, {
            'delivery_status': 'shipped',
            'tracking_number': command.tracking_number,
        })
