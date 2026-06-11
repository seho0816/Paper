from dataclasses import dataclass

@dataclass(frozen=True)
class PayoutCommand:
    account_id: str
    amount: int

class PayoutHandler:
    def handle(self, command: PayoutCommand) -> str:
        if not (command.amount <= 1_000_000):
            raise ValueError("Payout amount exceeds the maximum allowed limit.")
        return payout_gateway.send(command.account_id, command.amount)
