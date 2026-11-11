"""
Base Dataset Loader Interface.

Provides a unified contract for loading, inspecting, and chunk-processing public IoT datasets.
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, Iterator, List, Optional, Tuple

from training.feature_contract import StandardRecord
from training.preprocessing.validation import validate_flow_record


@dataclass
class DatasetMetadata:
    name: str
    source_url: str
    format: str
    description: str
    supported_classes: List[str]
    total_records: int = 0
    valid_records: int = 0
    rejected_records: int = 0
    duplicate_records: int = 0
    attributes: Dict[str, Any] = field(default_factory=dict)


class BaseDatasetLoader(ABC):
    """Abstract interface implemented by all real-world dataset loaders."""

    def __init__(self, data_path: Path | str, name: str):
        self.data_path = Path(data_path)
        self.name = name
        self.stats = {
            "total_rows": 0,
            "valid_rows": 0,
            "rejected_rows": 0,
            "duplicate_rows": 0,
        }

    @abstractmethod
    def inspect_schema(self) -> Dict[str, Any]:
        """Inspects sample headers and columns without loading entire dataset."""
        pass

    @abstractmethod
    def load_chunks(
        self, chunk_size: int = 10000, limit: Optional[int] = None
    ) -> Iterator[List[StandardRecord]]:
        """Yields chunks of validated StandardRecord instances."""
        pass

    def load_all(self, limit: Optional[int] = None) -> List[StandardRecord]:
        """Convenience method to load all records up to limit."""
        records: List[StandardRecord] = []
        for chunk in self.load_chunks(chunk_size=10000, limit=limit):
            records.extend(chunk)
            if limit and len(records) >= limit:
                return records[:limit]
        return records

    def get_summary(self) -> Dict[str, Any]:
        """Returns processing statistics."""
        return {
            "dataset_name": self.name,
            "data_path": str(self.data_path),
            **self.stats,
        }
