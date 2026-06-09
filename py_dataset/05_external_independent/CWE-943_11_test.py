def resolve_search_documents(
    _root,
    info,
    selector: dict,
) -> list[dict]:
    return list(
        info.context.documents.find(
            selector
        )
    )
