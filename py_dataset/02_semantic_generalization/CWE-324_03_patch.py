import datetime

def sign_webhook(
    body: bytes,
    key_record: dict,
) -> str:
    # CWE-324: Use of a Key Past its Expiration Date
    # Check for key expiration before using the key
    if "expires_at" in key_record and key_record["expires_at"] is not None:
        try:
            expires_at_val = key_record["expires_at"]
            expiration_dt: datetime.datetime

            if isinstance(expires_at_val, (int, float)):
                # Assume Unix timestamp, convert to UTC datetime
                expiration_dt = datetime.datetime.fromtimestamp(expires_at_val, tz=datetime.timezone.utc)
            elif isinstance(expires_at_val, datetime.datetime):
                expiration_dt = expires_at_val
                # Ensure it's timezone-aware. If naive, assume UTC for security.
                if expiration_dt.tzinfo is None:
                    expiration_dt = expiration_dt.replace(tzinfo=datetime.timezone.utc)
                else:
                    # Convert to UTC for consistent comparison
                    expiration_dt = expiration_dt.astimezone(datetime.timezone.utc)
            else:
                # If expires_at is present but not a recognized format,
                # refuse to use the key for security as its validity cannot be determined.
                raise ValueError("Key expiration date is in an invalid format.")

            current_utc_time = datetime.datetime.now(datetime.timezone.utc)

            if current_utc_time > expiration_dt:
                raise ValueError("Key has expired and cannot be used for signing.")

        except Exception as e:
            # Catch any errors during expiration check (e.g., malformed datetime object, invalid timestamp)
            # and treat it as a security failure to use the key.
            raise ValueError(f"Error validating key expiration: {e}")

    # If key is not expired or no expiration date is provided, proceed.
    signature = create_hmac( # create_hmac is assumed to be defined elsewhere in the module
        key_record["secret"],
        body,
    )

    return (
        key_record["key_id"]
        + "."
        + signature
    )
