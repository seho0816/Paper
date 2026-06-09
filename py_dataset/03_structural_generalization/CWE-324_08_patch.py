import time

class RotatingKeyProvider:
    def __init__(
        self,
        keys: list[dict],
    ) -> None:
        self._keys = keys
        self._current_key_index = 0

    def current(
        self,
    ) -> dict:
        if not self._keys:
            raise IndexError("No keys available for RotatingKeyProvider.")

        key = self._keys[self._current_key_index]
        self._current_key_index = (self._current_key_index + 1) % len(self._keys)
        
        # CWE-324: 키 만료일자(exp) 검증 추가
        if key.get("exp", float('inf')) < time.time():
            raise ValueError("Key is expired")
            
        return key

class TokenService:
    def __init__(
        self,
        provider: RotatingKeyProvider,
    ) -> None:
        self._provider = provider

    def issue(
        self,
        claims: dict,
    ) -> str:
        key = self._provider.current()

        return encode_token(
            claims,
            key["secret"],
        )