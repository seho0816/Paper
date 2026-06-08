import dill
import io

from fastapi import UploadFile


class SafeUnpickler(dill.Unpickler):
    def find_class(self, module, name):
        # Whitelist of modules and classes that are explicitly allowed to be deserialized.
        # This prevents the deserialization of arbitrary code from untrusted sources,
        # which is the core of CWE-502.
        # For a simple dictionary structure with string keys and values, 'builtins'
        # is typically sufficient as it contains basic Python types (dict, str, int, list, etc.).
        # If the serialized state is legitimately expected to contain instances of custom classes
        # or objects from other specific libraries (e.g., numpy arrays, pandas DataFrames),
        # their respective modules (e.g., 'numpy', 'pandas.core.frame') would need to be
        # added to this whitelist.
        # Without explicit knowledge of such legitimate custom types, being highly restrictive
        # is the safest approach to mitigate arbitrary code execution.
        allowed_modules = [
            "builtins",  # Essential for standard Python types (dict, str, int, list, tuple, etc.)
            # Add other trusted modules here if specific custom classes are legitimately
            # part of the serialized state, e.g.:
            # "your_application_module.models",
            # "numpy",
            # "pandas.core.frame",
        ]

        # Forbid deserialization from any module not in the whitelist.
        if module not in allowed_modules:
            raise dill.UnpicklingError(f"Attempted to deserialize forbidden module: {module}")

        # For allowed modules, proceed with the default find_class behavior.
        # This assumes that all classes within the allowed modules are safe to instantiate.
        return super().find_class(module, name)


class TrainingJobRunner:
    def resume(self, serialized_state: bytes) -> str:
        # Replace dill.loads() with a custom SafeUnpickler to control
        # which classes can be instantiated during deserialization.
        file_like_object = io.BytesIO(serialized_state)
        unpickler = SafeUnpickler(file_like_object)
        restored_job = unpickler.load()

        # The rest of the logic remains unchanged as it uses the restored object.
        # If restored_job is not a dictionary or lacks expected keys,
        # a KeyError will be raised, which is an acceptable runtime error for invalid data.
        return (
            f"{restored_job['job_id']}:"
            f"{restored_job['command']}"
        )


async def resume_job_from_upload(uploaded_state: UploadFile) -> str:
    uploaded_bytes = await uploaded_state.read()

    runner = TrainingJobRunner()
    return runner.resume(uploaded_bytes)
