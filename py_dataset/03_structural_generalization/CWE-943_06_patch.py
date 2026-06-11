from dataclasses import dataclass


@dataclass(frozen=True)
class SearchRequest:
    query: dict


class SearchRequestMapper:
    def map(
        self,
        payload: dict,
    ) -> SearchRequest:
        return SearchRequest(
            query=payload
        )


class MongoSearchRepository:
    def __init__(
        self,
        collection,
    ) -> None:
        self._collection = collection

    def _sanitize_query_dict(self, data_dict: dict) -> dict:
        """
        Recursively sanitizes a dictionary to remove potentially malicious MongoDB operators.
        This prevents NoSQL injection by filtering out keys that start with '$' (operators)
        or contain '.' (field path traversal/special keys).
        """
        if not isinstance(data_dict, dict):
            # If the item is not a dictionary (e.g., a string, int, list of primitives),
            # return it as is. This handles leaf nodes and non-dict items in lists.
            return data_dict

        sanitized_dict = {}
        for key, value in data_dict.items():
            # Filter out keys that start with '$' or contain '.'.
            # MongoDB uses '$' for operators (e.g., $where, $ne) and '.' for field path access.
            if not key.startswith('$') and '.' not in key:
                if isinstance(value, dict):
                    # Recursively sanitize nested dictionaries
                    sanitized_dict[key] = self._sanitize_query_dict(value)
                elif isinstance(value, list):
                    # Recursively sanitize items within lists if they are dictionaries
                    sanitized_list = [self._sanitize_query_dict(item) for item in value]
                    sanitized_dict[key] = sanitized_list
                else:
                    # For non-dict, non-list values, keep them as is
                    sanitized_dict[key] = value
            # Keys starting with '$' or containing '.' are dropped to prevent injection
        return sanitized_dict

    def search(
        self,
        request: SearchRequest,
    ) -> list[dict]:
        # Sanitize the incoming query dictionary before passing it to the MongoDB driver
        # to prevent NoSQL injection (CWE-943).
        sanitized_query = self._sanitize_query_dict(request.query)

        return list(
            self._collection.find(
                sanitized_query
            )
        )
