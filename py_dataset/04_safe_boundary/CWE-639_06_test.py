from dataclasses import dataclass


@dataclass(frozen=True)
class Order:
    order_id: str
    owner_id: str
    total: int


class OrderRepository:
    def __init__(self) -> None:
        self._orders = {
            "order-1": Order(
                order_id="order-1",
                owner_id="member-1",
                total=45000,
            ),
        }

    def find_by_id_and_owner(
        self,
        order_id: str,
        owner_id: str,
    ) -> Order | None:
        order = self._orders.get(order_id)

        if order is None:
            return None

        if order.owner_id != owner_id:
            return None

        return order


def read_order(
    repository: OrderRepository,
    order_id: str,
    current_user_id: str,
) -> Order | None:
    return repository.find_by_id_and_owner(
        order_id,
        current_user_id,
    )
