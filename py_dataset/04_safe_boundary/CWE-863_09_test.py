def approve_document(
    actor: dict,
    document: dict,
) -> None:
    if actor.get("role") not in {
        "reviewer",
        "administrator",
    }:
        raise PermissionError(
            "approval denied"
        )

    if document.get("status") != "pending":
        raise ValueError(
            "document is not pending"
        )

    mark_document_approved(
        document["id"],
        actor["id"],
    )
