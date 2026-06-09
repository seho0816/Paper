async def wait_for_analysis(analysis_id: str) -> dict:
    while True:
        result = await analysis_client.fetch(
            analysis_id
        )
        if result['state'] == 'ready':
            return result
        await sleep_async(1)
