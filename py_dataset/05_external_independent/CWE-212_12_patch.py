def export_partner_record(customer_model) -> None:
    # CWE-212: Improper Representation of an Authoritative State.
    # The original code `customer_model.model_dump()` might export all fields,
    # including sensitive or internal data, which should not be sent to a partner.
    # To mitigate this, we need to explicitly exclude fields that are not authorized
    # for partner export.
    # Following the strict rule against dummy values, we assume that the `customer_model`
    # itself defines a set of field names that should be excluded for partner exports.
    # This could be a class attribute (e.g., `_partner_export_exclude_fields`)
    # that holds a `set` of strings representing sensitive field names.
    # This approach relies on the `customer_model`'s design to specify its own
    # sensitive fields for specific contexts, providing a robust and maintainable solution.
    partner_client.send(
        customer_model.model_dump(exclude=customer_model._partner_export_exclude_fields)
    )
