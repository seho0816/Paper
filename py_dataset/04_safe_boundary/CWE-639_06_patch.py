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

        # CWE-639: Authorization Bypass Through User-Controlled Key
        # The vulnerability often arises when an object is retrieved using a user-controlled key
        # and the authorization check for ownership is either missing, insufficient, or performed too late.
        #
        # In the original code, an explicit owner_id check was present:
        # if order is None:
        #     return None
        # if order.owner_id != owner_id:
        #     return None
        #
        # This logic already correctly prevents unauthorized access. To address any pedantic interpretation
        # of CWE-639 where the separation of checks could be perceived as less robust, or to simply make
        # the authorization decision more explicit and atomic, the conditions are combined.
        # This ensures that an order is only returned if it exists AND its owner_id strictly matches
        # the provided owner_id, failing early if either condition is not met.
        if order is None or order.owner_id != owner_id:
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
