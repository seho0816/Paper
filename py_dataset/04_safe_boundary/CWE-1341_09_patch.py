import threading


render_slots = threading.BoundedSemaphore(
    4
)


def render_report(
    report_id: str,
) -> None:
    with render_slots:
        create_report(
            report_id
        )

