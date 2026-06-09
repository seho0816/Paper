from pathlib import Path

import torch


def activate_uploaded_checkpoint(
    checkpoint_path: Path,
) -> object:
    checkpoint = torch.load(
        checkpoint_path,
        map_location="cpu",
        weights_only=True,
    )

    return checkpoint
