async def wait_for_analysis(analysis_id: str) -> dict:
    MAX_RETRIES = 600  # Limits the loop to a maximum of 600 attempts (e.g., 10 minutes with 1-second sleeps)
    retries = 0

    while True:
        result = await analysis_client.fetch(
            analysis_id
        )
        if result['state'] == 'ready':
            return result
        
        retries += 1
        if retries > MAX_RETRIES:
            raise TimeoutError(f"Analysis {analysis_id} did not become ready after {MAX_RETRIES} attempts.")
        
        await sleep_async(1)
