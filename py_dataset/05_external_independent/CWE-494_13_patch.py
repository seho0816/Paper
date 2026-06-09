import torch


def load_remote_model(
    repository: str,
    model_name: str,
):
    return torch.hub.load(
        repository,
        model_name,
        source="github",
        trust_repo=False,
    )
