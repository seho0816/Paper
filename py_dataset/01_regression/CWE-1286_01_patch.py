import json


class PromotionRuleImporter:
    def import_text(self, raw_rule: str) -> dict:
        # CWE-1286: Improper Neutralization of Expressions in a Configuration.
        # The vulnerable code directly accesses dictionary keys (e.g., parsed_rule["rule_name"]).
        # If the input `raw_rule` (the configuration) is missing any of these expected keys,
        # a KeyError would be raised, leading to an unhandled runtime error and potentially
        # a denial of service. This represents an "improper expression" in the configuration
        # (an incomplete rule definition) that is not properly "neutralized".
        #
        # To fix this, we use the dictionary's `.get()` method. This allows us to
        # safely retrieve a value for a key. If the key is not present, `.get()` returns
        # `None` by default (or a specified default value), preventing a KeyError
        # and ensuring the method always returns a dictionary with a consistent structure,
        # thus neutralizing the vulnerability caused by incomplete configurations.
        #
        # Note: Handling `json.JSONDecodeError` for malformed JSON input is also good practice
        # for robustness, but it addresses a different type of issue (malformed *overall* configuration
        # rather than "expressions *in*" a configuration) and is omitted here to strictly adhere
        # to fixing *only* CWE-1286 as per the prompt.
        parsed_rule = json.loads(raw_rule)

        return {
            "rule_name": parsed_rule.get("rule_name"),
            "when": parsed_rule.get("when"),
            "then": parsed_rule.get("then"),
        }
