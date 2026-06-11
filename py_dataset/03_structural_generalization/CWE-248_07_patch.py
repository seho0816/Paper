import logging

class ScheduledJobRunner:
    def run(
        self,
        jobs: list[dict],
    ) -> None:
        for job in jobs:
            try:
                # Ensure 'type' key exists before accessing
                job_type = job.get("type")
                if job_type is None:
                    logging.error(f"Job skipped: 'type' key missing in job definition: {job}")
                    continue

                handler = load_job_handler(job_type)

                # Ensure 'payload' key exists before accessing
                job_payload = job.get("payload")
                if job_payload is None:
                    logging.error(f"Job skipped: 'payload' key missing in job definition for type '{job_type}': {job}")
                    continue

                if not hasattr(handler, 'execute') or not callable(handler.execute):
                    logging.error(f"Job skipped: Handler for type '{job_type}' does not have an executable 'execute' method: {handler}")
                    continue

                handler.execute(job_payload)
            except KeyError as e:
                logging.error(f"Failed to process job due to missing key: {e}. Job details: {job}")
                # Continue to the next job if one fails
                continue
            except AttributeError as e:
                logging.error(f"Failed to process job due to handler attribute error: {e}. Job details: {job}")
                # Continue to the next job if one fails
                continue
            except Exception as e:
                # Catch any other unexpected exceptions during handler loading or execution
                logging.error(f"An unexpected error occurred while processing job: {e}. Job details: {job}")
                # Continue to the next job if one fails
                continue
