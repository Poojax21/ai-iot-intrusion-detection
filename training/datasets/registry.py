"""
Dataset Loader Registry and Factory.
"""

from pathlib import Path
from typing import Dict, List, Type
from training.datasets.base_loader import BaseDatasetLoader
from training.datasets.iot23_loader import IoT23Loader
from training.datasets.ciciot2023_loader import CICIoT2023Loader
from training.datasets.ton_iot_loader import TonIoTLoader
from training.datasets.bot_iot_loader import BotIoTLoader
from training.datasets.nbaiot_loader import NBaIoTLoader

LOADER_REGISTRY: Dict[str, Type[BaseDatasetLoader]] = {
    "iot23": IoT23Loader,
    "ciciot2023": CICIoT2023Loader,
    "ton_iot": TonIoTLoader,
    "bot_iot": BotIoTLoader,
    "nbaiot": NBaIoTLoader,
}


def register_dataset_loader(name: str, loader_cls: Type[BaseDatasetLoader]):
    """Registers a new custom dataset loader class."""
    LOADER_REGISTRY[name.lower()] = loader_cls


def get_dataset_loader(name: str, data_path: Path | str, **kwargs) -> BaseDatasetLoader:
    """Instantiates a registered dataset loader by key."""
    key = name.lower()
    if key not in LOADER_REGISTRY:
        raise ValueError(
            f"Unknown dataset '{name}'. Supported datasets: {list(LOADER_REGISTRY.keys())}"
        )
    return LOADER_REGISTRY[key](data_path, **kwargs)


def list_supported_datasets() -> List[str]:
    """Returns list of supported dataset keys."""
    return list(LOADER_REGISTRY.keys())
