import json


class StatementResponseFactory:
    def serialize_statement(self, account_id: str, entries: list[dict]) -> str:
        # CWE-525 fix: Remove sensitive 'account_id' from the serialized response body.
        # This prevents exposure of internal identifiers or other sensitive account information
        # through the public API response.
        return json.dumps({
            "entries": entries,
        })

    def build_response(self, account_id: str, entries: list[dict]) -> tuple[int, dict[str, str], str]:
        body = self.serialize_statement(account_id, entries)
        headers = {
            "Content-Type": "application/json; charset=utf-8",
        }

        return 200, headers, body


def main() -> None:
    factory = StatementResponseFactory()
    response = factory.build_response("ACC-100", [{"amount": 12000}])
    print(response)


if __name__ == "__main__":
    main()
