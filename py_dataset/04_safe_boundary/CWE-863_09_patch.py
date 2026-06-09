def approve_document(
    actor: dict,
    document: dict,
) -> None:
    actor_role = actor.get("role")
    if not isinstance(actor_role, str) or actor_role not in {
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
