import bcrypt

async def authenticate_motor(
    users_collection,
    request_body: dict,
) -> dict | None:
    # Extract and validate username and password from the request body.
    # This prevents arbitrary query operators from being injected through request_body
    # and ensures we're dealing with string credentials.
    if not isinstance(request_body, dict):
        return None

    username_input = request_body.get("username")
    password_input = request_body.get("password")

    if not isinstance(username_input, str) or not isinstance(password_input, str):
        return None

    # Query the database to find a user by the given username.
    # By constructing the query dictionary explicitly with a string `username_input`,
    # we prevent NoSQL injection via malicious operators in the `username` field itself
    # (e.g., {"username": {"$ne": "admin"}}) or other fields.
    user = await users_collection.find_one({"username": username_input})

    if user and user.get("hashed_password"):
        stored_hashed_password = user["hashed_password"]
        
        # Ensure the stored hashed password is in bytes for bcrypt.checkpw comparison.
        if isinstance(stored_hashed_password, str):
            stored_hashed_password_bytes = stored_hashed_password.encode('utf-8')
        elif isinstance(stored_hashed_password, bytes):
            stored_hashed_password_bytes = stored_hashed_password
        else:
            # Stored password is of an unexpected type, cannot verify.
            return None

        # Verify the provided plaintext password against the stored hashed password using bcrypt.
        # bcrypt.checkpw expects both the password and hashed_password to be bytes.
        if bcrypt.checkpw(password_input.encode('utf-8'), stored_hashed_password_bytes):
            # Authentication successful.
            # Create a mutable copy of the user document before modifying it.
            user_safe = dict(user)
            # Remove the hashed password from the document before returning for security best practices.
            if "hashed_password" in user_safe:
                del user_safe["hashed_password"]
            return user_safe
    
    return None
