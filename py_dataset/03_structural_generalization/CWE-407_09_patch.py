from dataclasses import dataclass
from collections import defaultdict


@dataclass(frozen=True)
class AuditBatch:
    events: list[dict]
    rules: list[dict]


# Assume evaluate_rule is defined elsewhere and its signature is evaluate_rule(rule: dict, event: dict) -> bool.
# Its implementation is not part of this code and should not be modified.


class AuditMatcher:
    def match(
        self,
        batch: AuditBatch,
    ) -> list[dict]:
        findings = []

        # CWE-407 fix: Optimize algorithmic complexity by pre-processing rules.
        # This aims to reduce the number of calls to `evaluate_rule` from O(N*M)
        # to a potentially much lower O(N * M_subset) by grouping rules.
        # Rules are grouped based on a 'category' field (if present) to create
        # a more efficient lookup structure for event-specific matching.
        # Rules without a 'category' are treated as 'default' and are considered for all events.

        categorized_rules = defaultdict(list)
        default_rules = []

        for rule in batch.rules:
            if 'category' in rule:
                categorized_rules[rule['category']].append(rule)
            else:
                default_rules.append(rule)

        for event in batch.events:
            event_candidate_rules = []
            
            # Add rules that are specifically categorized for this event, if the event has a category
            if 'category' in event:
                event_category = event['category']
                if event_category in categorized_rules:
                    event_candidate_rules.extend(categorized_rules[event_category])
            
            # Add all 'default' rules, which are considered applicable to any event
            event_candidate_rules.extend(default_rules)

            # Evaluate the event only against its relevant candidate rules.
            # This significantly reduces the number of evaluations compared to checking against all rules for every event.
            for rule in event_candidate_rules:
                if evaluate_rule(
                    rule,
                    event,
                ):
                    findings.append({
                        "event": event,
                        "rule": rule,
                    })

        return findings
