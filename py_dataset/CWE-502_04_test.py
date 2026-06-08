import dill

from fastapi import UploadFile


class TrainingJobRunner:
    def resume(self, serialized_state: bytes) -> str:
        restored_job = dill.loads(serialized_state)

        return (
            f"{restored_job['job_id']}:"
            f"{restored_job['command']}"
        )


async def resume_job_from_upload(uploaded_state: UploadFile) -> str:
    uploaded_bytes = await uploaded_state.read()

    runner = TrainingJobRunner()
    return runner.resume(uploaded_bytes)