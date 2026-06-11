import ast
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
        # CWE-94 (Improper Control of Generation of Code) vulnerability exists due to using eval()
        # with potentially untrusted input from rule.source.
        # To remove this vulnerability, eval() is replaced with ast.literal_eval().
        # ast.literal_eval() safely evaluates strings containing Python literals
        # (strings, numbers, tuples, lists, dicts, booleans, None) without executing arbitrary code.
        # This change restricts the 'rule.source' to be a safe literal.
        # Any attempt to pass non-literal expressions (e.g., expressions involving variables or functions)
        # will now result in a ValueError or SyntaxError, preventing code injection.
        # The 'context' argument remains in the method signature as required,
        # but is effectively unused by ast.literal_eval.
        try:
            return ast.literal_eval(rule.source)
        except (ValueError, SyntaxError) as e:
            raise ValueError(f"Rule source '{rule.source}' is not a safe literal expression and cannot be evaluated.") from e


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
