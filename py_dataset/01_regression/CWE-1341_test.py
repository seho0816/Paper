import threading


render_slots = threading.Semaphore(
    4
)


def render_report(
    report_id: str,
) -> None:
    render_slots.acquire()
    try:
        create_report(
            report_id
        )
    finally:
        render_slots.release()
    render_slots.release()
