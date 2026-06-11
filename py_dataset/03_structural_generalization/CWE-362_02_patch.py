import asyncio
from collections import defaultdict
from dataclasses import dataclass


@dataclass(frozen=True)
class ReservationCommand:
    product_id: str
    quantity: int


class StockRepository:
    def __init__(self) -> None:
        self._stock = {
            "product-7": 1,
        }

    async def read_quantity(
        self,
        product_id: str,
    ) -> int:
        await asyncio.sleep(0)
        return self._stock[product_id]

    async def save_quantity(
        self,
        product_id: str,
        quantity: int,
    ) -> None:
        await asyncio.sleep(0)
        self._stock[product_id] = quantity


class ReservationService:
    def __init__(
        self,
        repository: StockRepository,
    ) -> None:
        self._repository = repository
        # A dictionary to hold asyncio.Lock instances, one per product_id,
        # to prevent race conditions during concurrent reservation attempts for the same product.
        self._product_locks: defaultdict[str, asyncio.Lock] = defaultdict(asyncio.Lock)

    async def reserve(
        self,
        command: ReservationCommand,
    ) -> bool:
        # Acquire a lock specific to the product_id to ensure that the read-check-modify
        # sequence is atomic for that product, preventing race conditions (CWE-362).
        async with self._product_locks[command.product_id]:
            current_quantity = (
                await self._repository.read_quantity(
                    command.product_id,
                )
            )

            if current_quantity < command.quantity:
                return False

            await self._repository.save_quantity(
                command.product_id,
                current_quantity - command.quantity,
            )
            return True


repository = StockRepository()
service = ReservationService(repository)


async def run_concurrent_reservations() -> list[bool]:
    command = ReservationCommand(
        product_id="product-7",
        quantity=1,
    )

    return await asyncio.gather(
        service.reserve(command),
        service.reserve(command),
    )
