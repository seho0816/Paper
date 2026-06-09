def activate_subscription(request_json: dict) -> dict:
    monthly_fee = int(request_json["monthly_fee"])
    months = int(request_json["months"])
    charge = monthly_fee * months
    subscription_id = create_subscription(request_json["plan_id"], months)
    return {"subscription_id": subscription_id, "charge": charge}
