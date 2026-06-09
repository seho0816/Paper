from dataclasses import dataclass


@dataclass(frozen=True)
class ReportLabel:
    pattern: str
    values: dict


class ReportLabelService:
    def build(
        self,
        label: ReportLabel,
    ) -> str:
        return label.pattern % label.values
