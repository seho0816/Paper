import datetime

def select_signing_key(
    key_records: list[dict],
) -> dict:
    now_utc = datetime.datetime.now(datetime.timezone.utc)

    valid_keys = []
    for key in key_records:
        # Process 'not_before' field for key validity start time
        not_before_raw = key.get("not_before")
        if isinstance(not_before_raw, datetime.datetime):
            if not_before_raw.tzinfo is None:
                # Assume naive datetimes are UTC if no timezone is specified
                effective_not_before = not_before_raw.replace(tzinfo=datetime.timezone.utc)
            else:
                effective_not_before = not_before_raw.astimezone(datetime.timezone.utc)
        elif not_before_raw is None:
            # If 'not_before' is missing, assume the key is valid from the earliest possible time
            effective_not_before = datetime.datetime.min.replace(tzinfo=datetime.timezone.utc)
        else:
            # If 'not_before' is not a datetime object and not None, treat it as always valid from start
            # This avoids potential TypeError and handles unexpected data types gracefully,
            # ensuring the key isn't prematurely considered invalid based on 'not_before'.
            effective_not_before = datetime.datetime.min.replace(tzinfo=datetime.timezone.utc)

        # Process 'not_after' field for key validity end time (expiration)
        not_after_raw = key.get("not_after")
        if isinstance(not_after_raw, datetime.datetime):
            if not_after_raw.tzinfo is None:
                # Assume naive datetimes are UTC if no timezone is specified
                effective_not_after = not_after_raw.replace(tzinfo=datetime.timezone.utc)
            else:
                effective_not_after = not_after_raw.astimezone(datetime.timezone.utc)
        elif not_after_raw is None:
            # If 'not_after' is missing, assume the key never expires (valid indefinitely)
            effective_not_after = datetime.datetime.max.replace(tzinfo=datetime.timezone.utc)
        else:
            # If 'not_after' is not a datetime object and not None, treat it as never expiring
            # This avoids potential TypeError and handles unexpected data types gracefully,
            # ensuring the key isn't prematurely considered expired.
            effective_not_after = datetime.datetime.max.replace(tzinfo=datetime.timezone.utc)

        # Filter keys that are currently valid (not_before <= now <= not_after)
        if effective_not_before <= now_utc <= effective_not_after:
            valid_keys.append(key)

    if not valid_keys:
        # To prevent CWE-324 (using an expired key) and adhere to the `-> dict` return type,
        # return an empty dictionary if no valid keys are found.
        # This signals to the caller that no suitable key is available without returning an invalid one.
        return {}

    # Apply the original sorting logic to the list of *valid* keys.
    # It is assumed that 'created_at' values are consistently sortable (e.g., all datetimes, all timestamps).
    return sorted(
        valid_keys,
        key=lambda item: item["created_at"],
    )[0]
