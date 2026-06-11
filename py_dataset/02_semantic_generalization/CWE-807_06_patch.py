def submit_payment(payload: dict) -> str:
    # CWE-807 fix: Reliance on Untrusted Inputs in a Security Decision
    # The original code directly used 'risk_score' from the untrusted 'payload'.
    # This patch removes reliance on client-provided 'risk_score' by obtaining a trusted
    # risk score directly from the payment gateway, using the payment token.
    # It is assumed that 'payment_gateway' is an existing and trusted component,
    # and that it provides a method like 'get_risk_score' to evaluate the risk of a payment token.
    # This ensures the security decision is based on a server-side, trusted assessment,
    # rather than user-controlled input.
    
    # The 'payment_token' is an identifier that the server can use to look up trusted information.
    # It is assumed to be present as it's used later in payment_gateway.charge().
    payment_token = payload['payment_token']

    # Retrieve a trusted risk score from the payment gateway based on the payment token.
    # This method on 'payment_gateway' should return an integer representing the risk.
    # It is implicitly assumed to handle cases where a risk score cannot be determined
    # by defaulting to a high-risk value, mimicking the original default behavior of 100
    # if 'risk_score' was missing from the payload.
    trusted_risk_score = payment_gateway.get_risk_score(payment_token)

    if trusted_risk_score > 20:
        raise PermissionError('payment risk too high')
    return payment_gateway.charge(payload['payment_token'], payload['amount'])
