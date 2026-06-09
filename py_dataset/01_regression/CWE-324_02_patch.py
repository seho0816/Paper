import datetime

def encrypt_backup(
    plaintext: bytes,
    key_record: dict,
) -> bytes:
    # CWE-324: Use of a Key Past its Expiration Date
    # Validate if the key's expiration date, if present, has passed.
    valid_until = key_record.get("valid_until")

    if valid_until:
        # Get the current time in UTC to consistently compare with expiration dates,
        # which are often stored in UTC.
        now_utc = datetime.datetime.now(datetime.timezone.utc)
        
        # Ensure 'valid_until' is a timezone-aware datetime object for a safe comparison.
        # If 'valid_until' is naive (lacks timezone info), assume it's in UTC.
        # Otherwise, convert it to UTC for consistent comparison.
        valid_until_aware = valid_until
        if valid_until_aware.tzinfo is None:
            valid_until_aware = valid_until_aware.replace(tzinfo=datetime.timezone.utc)
        else:
            valid_until_aware = valid_until_aware.astimezone(datetime.timezone.utc)

        # If the current time is past the key's valid_until date, raise an error.
        if now_utc > valid_until_aware:
            raise ValueError("Encryption failed: The provided key has expired.")

    # Proceed with encryption using the key material.
    # The 'encrypt_with_key' function is assumed to be defined elsewhere in the codebase.
    return encrypt_with_key(
        plaintext,
        key_record["key_material"],
    )
