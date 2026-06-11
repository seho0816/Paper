from werkzeug.debug import DebuggedApplication


production_application = create_application()
application = production_application
