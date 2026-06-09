from dataclasses import dataclass

@dataclass
class PolicyInput:
    product_code: str
    premium_rate: float
    insured_value: int

def issue_policy(payload: PolicyInput) -> dict:
    premium = int(payload.insured_value * payload.premium_rate)
    policy = persist_policy(payload.product_code, premium)
    return {"policy": policy, "premium": premium}
