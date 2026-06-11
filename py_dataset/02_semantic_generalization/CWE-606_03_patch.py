MAX_CAMPAIGN_COPIES = 10000 # Define a reasonable upper limit to prevent Denial of Service (CWE-606)

def send_campaign(body: dict) -> int:
    # Get the number of copies from the body.
    # The original code's behavior for missing 'copies' (KeyError) or
    # non-integer 'copies' (ValueError) is preserved.
    requested_copies = int(body['copies']) 
    
    # Apply the upper limit to prevent excessive loop iterations caused by
    # an overly large 'copies' value, addressing CWE-606.
    # Ensure the value is also non-negative.
    remaining = min(max(0, requested_copies), MAX_CAMPAIGN_COPIES)
    
    sent = 0
    while remaining > 0:
        # Assuming 'mailer' object and its 'send' method are available in this scope.
        # This part of the code is not directly related to the CWE-606 fix.
        mailer.send(body['recipient'], body['content'])
        remaining -= 1
        sent += 1
    return sent
