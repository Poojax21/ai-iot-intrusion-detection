"""
CICIoT2023 Dataset Loader.

Loads the UNB CICIoT2023 tabular flow features using chunked pandas processing.
Handles infinity values, NaN replacements, case variations in column headers,
and preserves the comprehensive 46 statistical features.
"""

from pathlib import Path
from typing import Any, Dict, Iterator, List, Optional
import pandas as pd
import numpy as np

from training.datasets.base_loader import BaseDatasetLoader
from training.feature_contract import StandardRecord
from training.preprocessing.label_normalizer import label_normalizer
from training.preprocessing.missing_values import clean_numeric
from training.preprocessing.protocol_normalizer import normalize_protocol


class CICIoT2023Loader(BaseDatasetLoader):
    """Chunked CSV loader for UNB CICIoT2023 dataset."""

    def __init__(self, data_path: Path | str):
        super().__init__(data_path, name="ciciot2023")

    def inspect_schema(self) -> Dict[str, Any]:
        """Inspects CSV header and sample row."""
        if not self.data_path.exists():
            raise FileNotFoundError(f"File not found: {self.data_path}")

        # Read first row only
        df_head = pd.read_csv(self.data_path, nrows=2)
        columns = list(df_head.columns)

        return {
            "dataset_name": self.name,
            "format": "csv",
            "columns": columns,
            "column_count": len(columns),
            "sample_labels": df_head["label"].tolist() if "label" in df_head.columns else [],
        }

    def load_chunks(
        self, chunk_size: int = 10000, limit: Optional[int] = None
    ) -> Iterator[List[StandardRecord]]:
        """Processes the CSV in chunksize batches without unbounded memory growth."""
        if not self.data_path.exists():
            raise FileNotFoundError(f"File not found: {self.data_path}")

        # Stream via pandas iterator
        csv_iterator = pd.read_csv(self.data_path, chunksize=chunk_size, low_memory=False)

        for df_chunk in csv_iterator:
            self.stats["total_rows"] += len(df_chunk)

            # Normalize column names: strip and lowercase
            df_chunk.columns = [c.strip() for c in df_chunk.columns]
            col_map = {c.lower(): c for c in df_chunk.columns}

            # Replace inf, -inf with NaN, then clean
            df_chunk.replace([np.inf, -np.inf], np.nan, inplace=True)

            chunk_records: List[StandardRecord] = []
            for _, row in df_chunk.iterrows():
                row_dict = row.to_dict()

                raw_label = str(row_dict.get("label", row_dict.get("Label", "BenignTraffic")))
                norm_res = label_normalizer.normalize(raw_label, dataset_name="ciciot2023")

                # Extract available statistical attributes
                duration = clean_numeric(row_dict.get("flow_duration", row_dict.get("Duration", 0.0)))
                total_bytes = clean_numeric(row_dict.get("Tot sum", row_dict.get("Tot size", 0.0)), target_type=int)
                total_pkts = clean_numeric(row_dict.get("Number", 0.0), target_type=int)
                proto_raw = row_dict.get("Protocol Type", row_dict.get("protocol", "tcp"))

                # In CICIoT2023 CSV, individual 5-tuples are omitted for privacy/aggregation;
                # synthesize deterministic identifier from dataset name and row index
                rec = StandardRecord(
                    timestamp=clean_numeric(row_dict.get("ts", 0.0)),
                    source_ip="192.168.1.100",
                    destination_ip="203.0.113.1",
                    source_port=clean_numeric(row_dict.get("src_port", 0), target_type=int),
                    destination_port=clean_numeric(row_dict.get("dst_port", 80), target_type=int),
                    protocol=normalize_protocol(proto_raw),
                    duration=max(0.0, duration),
                    source_bytes=int(total_bytes * 0.5),
                    destination_bytes=int(total_bytes * 0.5),
                    source_packets=max(1, int(total_pkts * 0.5)),
                    destination_packets=max(0, int(total_pkts * 0.5)),
                    connection_state="SF",
                    source_device_id=f"ciciot-dev-{norm_res.normalized_label.value.lower()}",
                    capture_id="ciciot2023-batch",
                    scenario_id=norm_res.attack_category,
                    original_label=norm_res.original_label,
                    normalized_label=norm_res.normalized_label.value,
                    dataset_name=self.name,
                    extra_features=row_dict,
                )

                self.stats["valid_rows"] += 1
                chunk_records.append(rec)

                if limit and self.stats["valid_rows"] >= limit:
                    yield chunk_records
                    return

            if chunk_records:
                yield chunk_records
