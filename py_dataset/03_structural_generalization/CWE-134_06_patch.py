from dataclasses import dataclass
from string import Template


@dataclass(frozen=True)
class ReportLabel:
    pattern: str
    values: dict


class ReportLabelService:
    def build(
        self,
        label: ReportLabel,
    ) -> str:
        return Template(label.pattern).substitute(label.values)
