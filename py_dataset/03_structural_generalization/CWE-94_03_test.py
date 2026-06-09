from dataclasses import dataclass


@dataclass(frozen=True)
class PricingRule:
    name: str
    source: str


class RuleRepository:
    def __init__(self) -> None:
        self._rules: dict[str, PricingRule] = {}

    def save(
        self,
        rule: PricingRule,
    ) -> None:
        self._rules[rule.name] = rule

    def find(
        self,
        name: str,
    ) -> PricingRule:
        return self._rules[name]


class RuleEngine:
    def evaluate(
        self,
        rule: PricingRule,
        context: dict,
    ) -> object:
        return eval(
            rule.source,
            {},
            context,
        )


class PricingService:
    def __init__(
        self,
        repository: RuleRepository,
        engine: RuleEngine,
    ) -> None:
        self._repository = repository
        self._engine = engine

    def calculate(
        self,
        rule_name: str,
        context: dict,
    ) -> object:
        rule = self._repository.find(
            rule_name,
        )

        return self._engine.evaluate(
            rule,
            context,
        )
