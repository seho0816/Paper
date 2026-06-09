from flask_socketio import SocketIO, emit

socketio = SocketIO()


@socketio.on("admin_command")
def handle_admin_command(
    message: dict,
) -> None:
    if message.get("action") == "reload_config":
        reload_runtime_config()
        emit(
            "admin_result",
            {"ok": True},
        )
