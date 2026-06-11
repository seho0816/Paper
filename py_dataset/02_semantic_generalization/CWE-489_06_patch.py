ENABLE_DATABASE_DUMP = False


def dump_database_route() -> bytes:
    if not ENABLE_DATABASE_DUMP:
        raise PermissionError(
            'diagnostics disabled'
        )
    return database.export_all_tables()
