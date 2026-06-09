from dataclasses import dataclass


@dataclass(frozen=True)
class LoginSelector:
    values: dict


class MongoAccountRepository:
    def __init__(
        self,
        collection,
    ) -> None:
        self._collection = collection

    def _is_safe_mongo_value(self, value) -> bool:
        """
        Recursively checks if a value is safe for direct use in a MongoDB query
        (i.e., does not contain MongoDB operators or malicious structures).
        Returns True if safe, False otherwise.
        """
        if isinstance(value, dict):
            for k, v in value.items():
                if not isinstance(k, str) or k.startswith('$'):
                    return False  # Key is not a string or starts with '$' (operator)
                if not self._is_safe_mongo_value(v):
                    return False  # Nested value is not safe
            return True
        elif isinstance(value, (list, tuple)):
            for item in value:
                if not self._is_safe_mongo_value(item):
                    return False
            return True
        else:
            # Primitive types (str, int, float, bool, None) are considered safe
            return True

    def _build_safe_query(self, input_dict: dict) -> dict:
        """
        Constructs a safe MongoDB query dictionary from user-provided input.
        - Filters out top-level keys that start with '$'.
        - Recursively checks all values to ensure no MongoDB operators are injected.
        """
        safe_query = {}
        for key, value in input_dict.items():
            if not isinstance(key, str):
                continue  # MongoDB field names must be strings
            if key.startswith('$'):
                continue  # Reject top-level keys that are MongoDB operators
            
            # Check if the value itself is safe (recursively)
            if self._is_safe_mongo_value(value):
                safe_query[key] = value
            else:
                # If a value contains an operator, skip this key-value pair.
                # This ensures that even nested operator injections are prevented.
                continue 
        return safe_query

    def find_login(
        self,
        selector: LoginSelector,
    ) -> dict | None:
        # Sanitize the selector values to prevent NoSQL injection (CWE-943)
        safe_selector_values = self._build_safe_query(selector.values)
        if not safe_selector_values:
            # If the sanitized query is empty, it means no valid login criteria were provided
            # or the input was entirely malicious. In a login context, this should result in no match.
            return None
        return self._collection.find_one(
            safe_selector_values
        )
