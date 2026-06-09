def approve_customer_export(actor_id: str, export_id: str) -> str:
    export_repository.approve(
        export_id,
        actor_id,
    )
    return export_queue.enqueue(
        export_id
    )
