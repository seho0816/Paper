from werkzeug.debug import DebuggedApplication


production_application = create_application()
application = DebuggedApplication(
    production_application,
    evalex=True,
)
