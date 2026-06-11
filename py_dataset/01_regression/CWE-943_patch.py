def login(
    users,
    request_json: dict,
):
    query = {}
    
    # Define the expected fields for login and their required types.
    # This prevents attackers from injecting MongoDB operators (which are dictionaries)
    # where a simple string or primitive type is expected.
    expected_fields = {
        "username": str,
        "password": str,
    }

    for field_name, expected_type in expected_fields.items():
        value = request_json.get(field_name)
        
        # Ensure the value exists and is of the expected type.
        # This explicitly validates the type, preventing NoSQL injection
        # where an attacker might pass a dictionary like {"$ne": "admin"}
        # instead of a simple string for username/password.
        if value is not None and isinstance(value, expected_type):
            query[field_name] = value
        else:
            # If the value is missing or its type is incorrect,
            # consider it an invalid login attempt and return None.
            # This prevents further processing of potentially malicious or malformed input.
            return None

    # For a successful login attempt, both username and password must be present
    # in the sanitized query.
    if "username" not in query or "password" not in query:
        return None

    return users.find_one(query)
