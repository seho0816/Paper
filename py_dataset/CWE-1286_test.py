import json


class PromotionRuleImporter:
    def import_text(self, raw_rule: str) -> dict:
        parsed_rule = json.loads(raw_rule)

        return {
            "rule_name": parsed_rule["rule_name"],
            "when": parsed_rule["when"],
            "then": parsed_rule["then"],
        }
