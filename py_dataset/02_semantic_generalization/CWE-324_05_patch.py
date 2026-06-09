import datetime

DEFAULT_CACHE_TTL_SECONDS = 3600

def cached_signing_key(
    cache,
    key_id: str,
) -> dict:
    cached_entry = cache.get(key_id)
    now_utc = datetime.datetime.now(datetime.timezone.utc)

    if cached_entry is not None:
        if isinstance(cached_entry, dict) and 'expires_at' in cached_entry and 'key' in cached_entry:
            if isinstance(cached_entry['expires_at'], datetime.datetime):
                if cached_entry['expires_at'] > now_utc:
                    return cached_entry['key']

    loaded_key_data = key_repository.load(key_id)
    if not loaded_key_data:
        return None

    # CWE-324: 로드된 키 자체가 만료(exp)되었는지 절대적으로 검증 (연장 불가)
    if isinstance(loaded_key_data, dict) and 'exp' in loaded_key_data:
        try:
            key_exp = datetime.datetime.fromtimestamp(loaded_key_data['exp'], tz=datetime.timezone.utc)
            if key_exp <= now_utc:
                raise ValueError("The signing key has expired.")
        except (TypeError, ValueError):
            raise ValueError("Invalid expiration format.")

    expires_at = now_utc + datetime.timedelta(seconds=DEFAULT_CACHE_TTL_SECONDS)
    
    cache.set(
        key_id,
        {
            'key': loaded_key_data,
            'expires_at': expires_at
        }
    )

    return loaded_key_data