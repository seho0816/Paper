PLAN_FEES = {
    "basic_plan": 10,
    "premium_plan": 25,
    "enterprise_plan": 50,
    # In a real application, these values would be loaded from a secure configuration,
    # database, or an external service. The key is that they are server-controlled
    # and not provided by the client.
}

# Assume create_subscription is an externally defined function
# that handles the creation of the subscription based on a plan_id and duration.
# Its signature is expected to be: def create_subscription(plan_id: str, months: int) -> str:

def activate_subscription(request_json: dict) -> dict:
    plan_id = request_json["plan_id"]
    
    # CWE-472 Fix: Retrieve the monthly_fee from a trusted, server-side source
    # (e.g., PLAN_FEES dictionary or a database lookup) using the plan_id,
    # instead of trusting the client-provided "monthly_fee" from request_json.
    if plan_id not in PLAN_FEES:
        # Handle cases where an invalid plan_id is provided.
        # This prevents using an arbitrary, untrusted fee value.
        raise ValueError(f"Invalid plan_id provided: {plan_id}")
        
    monthly_fee = PLAN_FEES[plan_id]
    
    months = int(request_json["months"])
    
    # The charge calculation now uses the server-controlled monthly_fee.
    charge = monthly_fee * months
    
    subscription_id = create_subscription(plan_id, months)
    
    return {"subscription_id": subscription_id, "charge": charge}
