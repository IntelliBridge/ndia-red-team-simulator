"""Download CIFAR-10, train the bundled CPU model, and write reproducible assets."""

from __future__ import annotations

import argparse
import json
import random
import warnings
from pathlib import Path
from typing import Any

import numpy as np

from redsim.targets.cifar10_assets import (
    MANIFEST_FILENAME,
    TEST_CACHE_FILENAME,
    WEIGHTS_FILENAME,
    build_small_cnn,
    sha256_file,
)


def set_deterministic_seed(seed: int) -> None:
    import torch

    random.seed(seed)
    np.random.seed(seed)
    torch.manual_seed(seed)
    torch.use_deterministic_algorithms(True)


class HuggingFaceCifar10Dataset:
    """Adapt a Hugging Face CIFAR-10 split to Torch's dataset interface."""

    def __init__(self, split: Any) -> None:
        from torchvision.transforms import ToTensor

        self._split = split
        self._to_tensor = ToTensor()

    def __len__(self) -> int:
        return len(self._split)

    def __getitem__(self, index: int) -> tuple[Any, int]:
        row = self._split[index]
        return self._to_tensor(row["img"]), int(row["label"])


def load_cifar10(data_dir: Path) -> tuple[Any, Any, str]:
    """Load the approved Hugging Face mirror, falling back to torchvision."""

    try:
        from datasets import load_dataset

        dataset = load_dataset("uoft-cs/cifar10", cache_dir=str(data_dir))
        return (
            HuggingFaceCifar10Dataset(dataset["train"]),
            HuggingFaceCifar10Dataset(dataset["test"]),
            "huggingface:uoft-cs/cifar10",
        )
    except Exception as exc:
        warnings.warn(
            f"Hugging Face CIFAR-10 mirror unavailable ({exc}); falling back to torchvision",
            RuntimeWarning,
            stacklevel=2,
        )

    from torchvision import datasets, transforms

    transform = transforms.ToTensor()
    train = datasets.CIFAR10(root=data_dir, train=True, download=True, transform=transform)
    test = datasets.CIFAR10(root=data_dir, train=False, download=True, transform=transform)
    return train, test, "torchvision.datasets.CIFAR10"


def train_model(
    train_dataset: Any,
    test_dataset: Any,
    *,
    epochs: int,
    batch_size: int,
    seed: int,
) -> tuple[Any, float]:
    import torch
    import torch.nn as nn
    from torch.utils.data import DataLoader

    generator = torch.Generator().manual_seed(seed)
    train_loader = DataLoader(
        train_dataset,
        batch_size=batch_size,
        shuffle=True,
        generator=generator,
        num_workers=0,
    )
    test_loader = DataLoader(test_dataset, batch_size=batch_size, shuffle=False, num_workers=0)
    model = build_small_cnn()
    optimizer = torch.optim.Adam(model.parameters(), lr=1e-3)
    loss_fn = nn.CrossEntropyLoss()

    model.train()
    for _ in range(epochs):
        for inputs, labels in train_loader:
            optimizer.zero_grad(set_to_none=True)
            loss_fn(model(inputs), labels).backward()
            optimizer.step()

    model.eval()
    correct = 0
    total = 0
    with torch.no_grad():
        for inputs, labels in test_loader:
            predictions = model(inputs).argmax(dim=1)
            correct += int((predictions == labels).sum())
            total += len(labels)
    return model, correct / total


def cache_test_split(test_dataset: Any, destination: Path) -> None:
    x = np.stack([np.asarray(test_dataset[index][0], dtype=np.float32) for index in range(len(test_dataset))])
    y = np.asarray([int(test_dataset[index][1]) for index in range(len(test_dataset))], dtype=np.int64)
    np.savez_compressed(destination, x=x, y=y)


def setup_assets(
    *,
    assets_dir: Path,
    data_dir: Path,
    epochs: int = 12,
    batch_size: int = 128,
    seed: int = 20260908,
) -> dict[str, Any]:
    import torch
    import torchvision

    if epochs <= 0 or batch_size <= 0:
        raise ValueError("epochs and batch size must be positive")
    assets_dir.mkdir(parents=True, exist_ok=True)
    data_dir.mkdir(parents=True, exist_ok=True)
    set_deterministic_seed(seed)
    train_dataset, test_dataset, dataset_source = load_cifar10(data_dir)
    model, accuracy = train_model(
        train_dataset,
        test_dataset,
        epochs=epochs,
        batch_size=batch_size,
        seed=seed,
    )

    weights_path = assets_dir / WEIGHTS_FILENAME
    cache_path = assets_dir / TEST_CACHE_FILENAME
    torch.save(model.state_dict(), weights_path)
    cache_test_split(test_dataset, cache_path)
    manifest = {
        "dataset": "CIFAR-10",
        "dataset_source": dataset_source,
        "dataset_split": "test",
        "model_architecture": "SmallCNN(2 conv blocks, 2 fully connected layers)",
        "training_seed": seed,
        "training_epochs": epochs,
        "batch_size": batch_size,
        "torch_version": torch.__version__,
        "torchvision_version": torchvision.__version__,
        "clean_test_accuracy": accuracy,
        "weights_sha256": sha256_file(weights_path),
        "test_cache_sha256": sha256_file(cache_path),
        "n_train": len(train_dataset),
        "n_test": len(test_dataset),
    }
    (assets_dir / MANIFEST_FILENAME).write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n"
    )
    return manifest


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--assets-dir", type=Path, default=Path("assets"))
    parser.add_argument("--data-dir", type=Path, default=Path("data"))
    parser.add_argument("--epochs", type=int, default=12)
    parser.add_argument("--batch-size", type=int, default=128)
    parser.add_argument("--seed", type=int, default=20260908)
    args = parser.parse_args()
    manifest = setup_assets(
        assets_dir=args.assets_dir,
        data_dir=args.data_dir,
        epochs=args.epochs,
        batch_size=args.batch_size,
        seed=args.seed,
    )
    print(json.dumps(manifest, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()