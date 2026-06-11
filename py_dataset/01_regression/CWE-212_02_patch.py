def migrate_customer(customer: dict) -> None:
    # Create a shallow copy of the customer dictionary to avoid modifying the original
    sanitized_customer = customer.copy()

    # Define sensitive keys that should be removed before releasing the information
    # This addresses CWE-212: Improper Removal of Sensitive Information Before Release
    sensitive_keys = ['password', 'social_security_number', 'credit_card_number']

    # Remove sensitive keys if they exist in the dictionary
    for key in sensitive_keys:
        sanitized_customer.pop(key, None) # .pop(key, None) safely removes the key if present, otherwise does nothing

    migration_client.send({
        "customer": sanitized_customer,  # Send the sanitized customer data
        "source": "legacy",
    })
