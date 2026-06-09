import asyncpg


async def search_audit_events(
    connection: asyncpg.Connection,
    actor: str,
    event_type: str,
) -> list[asyncpg.Record]:
    query = """
    SELECT event_id, actor, event_type
    FROM audit_events
    WHERE actor = $1
      AND event_type = $2
    """

    return await connection.fetch(
        query,
        actor,
        event_type,
    )
