from dataclasses import dataclass

@dataclass(frozen=True)
class ShipOrder:
    order_id: str
    tracking_number: str

class OrderWorkflowService:
    def ship(self, command: ShipOrder) -> None:
        # CWE-841 fix: Enforce behavioral policy to ensure an order can only be shipped if it's in a valid state.
        # This prevents operations like re-shipping an already shipped order, or shipping a cancelled order.
        # Assume 'order_repository' is an accessible dependency providing methods like 'get' and 'update'.
        current_order = order_repository.get(command.order_id)

        # Define the set of valid statuses an order must be in to be eligible for shipping.
        # This represents the business policy for order shipment.
        valid_pre_ship_statuses = {'created', 'processing', 'packed', 'ready_for_dispatch'}

        if not current_order:
            raise ValueError(f"Order with ID {command.order_id} not found.")
        
        current_status = current_order.get('delivery_status')
        if current_status not in valid_pre_ship_statuses:
            raise ValueError(f"Order {command.order_id} cannot be shipped. Current status: '{current_status}'. "
                             f"Must be one of: {', '.join(sorted(list(valid_pre_ship_statuses)))}")

        # If the order is in a valid state, proceed with updating its status to 'shipped'.
        order_repository.update(command.order_id, {
            'delivery_status': 'shipped',
            'tracking_number': command.tracking_number,
        })
