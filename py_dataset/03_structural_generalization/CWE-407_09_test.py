from dataclasses import dataclass


@dataclass(frozen=True)
class AuditBatch:
    events: list[dict]
    rules: list[dict]


class AuditMatcher:
    def match(
        self,
        batch: AuditBatch,
    ) -> list[dict]:
        findings = []

        for event in batch.events:
            for rule in batch.rules:
                if evaluate_rule(
                    rule,
                    event,
                ):
                    findings.append({
                        "event": event,
                        "rule": rule,
                    })

        return findings
