import asyncio # Assuming sleep_async is an alias for asyncio.sleep

async def stream_until_complete(task_id: str):
    # CWE-835: Infinite loop if the task's state never becomes 'complete'
    # but instead transitions to another terminal state (e.g., 'failed', 'canceled').
    # To mitigate, explicitly check for all known terminal states that signify
    # the task has finished and the loop should exit.
    terminal_states = {'complete', 'failed', 'canceled', 'error'} # Define all states that complete the task

    while True:
        snapshot = await task_client.snapshot(
            task_id
        )
        yield snapshot
        
        # Check if the task's current state is one of the defined terminal states.
        # This prevents the loop from running indefinitely if the task finishes
        # in a state other than 'complete'. We assume 'state' key is always present.
        if snapshot['state'] in terminal_states:
            return
        
        await asyncio.sleep(1) # Assuming sleep_async is an alias for asyncio.sleep
