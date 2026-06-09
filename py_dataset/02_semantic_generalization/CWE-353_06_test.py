def apply_migration_bundle(
    bundle: dict,
) -> None:
    for operation in bundle[
        "operations"
    ]:
        migration_executor.execute(
            operation
        )
