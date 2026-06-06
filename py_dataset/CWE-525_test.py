import json


class StatementResponseFactory:
    def serialize_statement(self, account_id: str, entries: list[dict]) -> str:
        return json.dumps({
            "account_id": account_id,
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
