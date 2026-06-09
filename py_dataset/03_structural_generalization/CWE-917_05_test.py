from dataclasses import dataclass


@dataclass(frozen=True)
class StoredRule:
    expression: str


class RuleRepository:
    def find(
        self,
        rule_id: str,
    ) -> StoredRule:
        return StoredRule(
            expression=database.load_rule(
                rule_id
            )
        )


class RuleService:
    def __init__(
        self,
        repository: RuleRepository,
        interpreter,
    ) -> None:
        self._repository = repository
        self._interpreter = interpreter

    def evaluate(
        self,
        rule_id: str,
        variables: dict,
    ):
        rule = self._repository.find(
            rule_id
        )

        return self._interpreter(
            rule.expression,
            variables,
        )
