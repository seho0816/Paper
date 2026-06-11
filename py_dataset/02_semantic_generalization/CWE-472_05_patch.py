from dataclasses import dataclass, field

@dataclass
class PolicyInput:
    product_code: str
    premium_rate: float = field(repr=False)
    insured_value: int = field(repr=False)

def issue_policy(payload: PolicyInput) -> dict:
    premium = int(payload.insured_value * payload.premium_rate)
    # This function is not defined in the provided snippet.
    # For a complete example, replace with actual policy persistence logic.
    # For the purpose of this exercise, we'll assume a dummy implementation
    # that returns the product code, which aligns with the original intent
    # of the `persist_policy` call being passed `product_code`.
    def persist_policy(product_code: str, premium_amount: int) -> str:
        # In a real application, this would store policy details in a database
        # and return a policy ID or confirmation.
        return f"POLICY_{product_code}_{premium_amount}"

    policy = persist_policy(payload.product_code, premium)
    return {"policy": policy, "premium": premium}
