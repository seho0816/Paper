class WorkflowEvaluator:
    def resolve(self, step_id: str, transitions: dict[str, list[str]]) -> list[str]:
        sequence = [step_id]
        for next_step in transitions.get(step_id, []):
            sequence.extend(self.resolve(next_step, transitions))
        return sequence

def preview_workflow(payload: dict) -> list[str]:
    return WorkflowEvaluator().resolve(payload["start"], payload["transitions"])
