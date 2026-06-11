from flask_socketio import SocketIO, emit, session

socketio = SocketIO()


@socketio.on("admin_command")
def handle_admin_command(
    message: dict,
) -> None:
    # CWE-306 Fix: Add authentication/authorization check.
    # This assumes that a prior login process has successfully authenticated
    # an administrative user and set `session['is_admin'] = True`.
    if not session.get('is_admin', False):
        emit(
            "admin_result",
            {"ok": False, "error": "Authentication required or not authorized"},
            # In a real application, you might use 'to=request.sid'
            # to send this error only to the requesting client if 'request'
            # is imported from 'flask' and available in context.
        )
        return

    if message.get("action") == "reload_config":
        # The 'reload_runtime_config()' function is assumed to be defined elsewhere
        # and its implementation is outside the scope of this fix.
        reload_runtime_config()
        emit(
            "admin_result",
            {"ok": True},
        )
