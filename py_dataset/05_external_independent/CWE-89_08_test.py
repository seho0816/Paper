import asyncpg


async def search_audit_events(
    connection: asyncpg.Connection,
    actor: str,
    event_type: str,
) -> list[asyncpg.Record]:
    query = f"""
    SELECT event_id, actor, event_type
    FROM audit_events
    WHERE actor = '{actor}'
      AND event_type = '{event_type}'
    """

    return await connection.fetch(
        query,
    )
