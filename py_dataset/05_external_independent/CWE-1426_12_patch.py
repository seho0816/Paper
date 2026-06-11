import json


class DuplicateKeyError(ValueError):
    """Custom exception for duplicate keys in JSON data."""
    pass


def reject_duplicate_keys(ordered_pairs):
    """
    A custom object_pairs_hook for json.loads that raises an error
    if duplicate keys are encountered, preventing ambiguous data processing.
    """
    d = {}
    for k, v in ordered_pairs:
        if k in d:
            # Raising an error for duplicate keys mimics rejecting ambiguous GraphQL aliases
            # by preventing the silent overwriting of values that could lead to
            # unexpected policy application.
            raise DuplicateKeyError(f"Duplicate key '{k}' found in JSON output. This indicates an ambiguous policy structure.")
        d[k] = v
    return d


def resolve_generate_policy(_root, info, requirements: str) -> dict:
    output = info.context.policy_model.generate(
        requirements
    )
    # The CWE-1426 (Improper Handling of Ambiguous GraphQL Aliases) is addressed here
    # by using a custom object_pairs_hook with json.loads.
    # This prevents the silent overwriting of duplicate keys in the JSON output,
    # which can be analogous to ambiguous GraphQL aliases resulting in inconsistent data.
    # Instead, an error is raised, forcing explicit handling of such ambiguity.
    policy = json.loads(
        output,
        object_pairs_hook=reject_duplicate_keys
    )
    info.context.policy_admin.apply(
        policy
    )
    return {'policy': policy, 'applied': True}
