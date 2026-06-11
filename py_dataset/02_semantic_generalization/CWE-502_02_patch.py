import dill
import io
import sys


class SafeDillUnpickler(dill.Unpickler):
    def find_class(self, module: str, name: str) -> type:
        # A whitelist of modules and classes that are explicitly allowed.
        # This list should be carefully curated based on the actual requirements
        # of the objects expected in the 'workflow'. Add only types that are
        # essential for your application and are known to be safe.
        # Deserializing custom classes or functions from untrusted sources
        # inherently poses a security risk.
        allowed_builtins = ['dict', 'list', 'tuple', 'set', 'str', 'bytes', 'int', 'float', 'bool', 'NoneType']
        
        # This dictionary defines what modules and classes are permitted.
        # It's crucial to keep this list as minimal and secure as possible.
        # If your workflow requires custom classes or functions, you must add them
        # here, but only if they are guaranteed to be non-malicious and safe to load.
        allowed_modules_and_classes = {
            'builtins': allowed_builtins,  # For Python 3 built-in types
            '__builtin__': allowed_builtins, # For Python 2 compatibility in dill's internal unpickler logic
            'collections': ['OrderedDict', 'defaultdict', 'deque'], # Common safe data structures
            'datetime': ['datetime', 'date', 'time', 'timedelta', 'timezone'], # Date and time objects
            # Add other necessary and SAFE modules/classes here. For example:
            # 'your_app_module': ['YourSafeWorkflowClass', 'YourSafeDataStructure'],
        }

        # Handle potential module name variations (e.g., Python 2 vs Python 3 for builtins)
        if module == "__builtin__":
            module = "builtins"

        # Check if the requested module and class are in our whitelist
        if module in allowed_modules_and_classes and name in allowed_modules_and_classes[module]:
            # If whitelisted, use the parent's find_class to resolve the type.
            # This ensures that dill's extended logic for finding classes (e.g., live objects)
            # is still utilized, but only for explicitly permitted types.
            return super().find_class(module, name)
        
        # If the module or class is not explicitly whitelisted, raise an error
        # to prevent deserialization of potentially unsafe or unexpected types.
        raise dill.UnpicklingError(f"Attempted to load potentially unsafe class: {module}.{name}")


def restore_workflow(
    serialized_workflow: bytes,
) -> object:
    # Use BytesIO to wrap the byte string, as dill.Unpickler expects a file-like object.
    file_obj = io.BytesIO(serialized_workflow)
    
    # Instantiate our custom unpickler that enforces a whitelist of allowed classes.
    unpickler = SafeDillUnpickler(file_obj)
    
    # Attempt to load the object using the restricted unpickler.
    return unpickler.load()
