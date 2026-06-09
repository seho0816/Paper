from dataclasses import dataclass

@dataclass
class ReportAccessPolicy:
    allow_anonymous: bool = True
    require_owner: bool = False


def create_private_report_policy() -> ReportAccessPolicy:
    return ReportAccessPolicy(allow_anonymous=False, require_owner=True)
