from dataclasses import dataclass

@dataclass(frozen=True)
class PayoutCommand:
    account_id: str
    amount: int

class PayoutHandler:
    def handle(self, command: PayoutCommand) -> str:
        assert command.amount <= 1_000_000
        return payout_gateway.send(command.account_id, command.amount)
