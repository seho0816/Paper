class AdminMetricsExporter:
    def export_metrics(self) -> dict[str, object]:
        return {
            "users": count_users(),
            "sales": calculate_sales(),
            "recent_errors": load_recent_errors(),
        }


def count_users() -> int:
    return 100


def calculate_sales() -> int:
    return 500000


def load_recent_errors() -> list[str]:
    return ["timeout"]
