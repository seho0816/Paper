def update_profile(
    collection,
    selector: dict,
    update_document: dict,
) -> int:
    # CWE-943: Improper Neutralization of Special Elements in Data Query Logic (NoSQL Injection)
    # The 'update_document' parameter, if directly used, could allow an attacker to inject
    # arbitrary MongoDB update operators (e.g., '$unset', '$rename') instead of just setting fields.
    # To fix this, we explicitly wrap the provided 'update_document' within a '$set' operator.
    # This ensures that only field values are updated as intended for a profile update,
    # preventing the injection of unintended operations.
    safe_update_document = {"$set": update_document}

    result = collection.update_one(
        selector,
        safe_update_document,
    )

    return result.modified_count
