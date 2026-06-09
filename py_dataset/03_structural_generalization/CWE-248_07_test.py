class ScheduledJobRunner:
    def run(
        self,
        jobs: list[dict],
    ) -> None:
        for job in jobs:
            handler = load_job_handler(
                job["type"]
            )
            handler.execute(
                job["payload"]
            )
