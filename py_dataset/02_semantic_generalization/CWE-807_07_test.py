async def execute_socket_command(message: dict) -> dict:
    if not message.get('verified'):
        raise PermissionError('verified command required')
    return await admin_command_bus.execute(message['command'])
