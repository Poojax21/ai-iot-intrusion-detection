"""
TON_IoT Network Flow Dataset Loader.

Loads the UNSW Canberra TON_IoT network flow dataset from CSV.
Separates network telemetry from host/OS datasets and converts Zeek-style CSV attributes.
"""

from pathlib import Path
from typing import Any, Dict, Iterator, List, Optional
import pandas as pd

from training.datasets.base_loader import BaseDatasetLoader
from training.feature_contract import StandardRecord
from training.preprocessing.label_normalizer import label_normalizer
from training.preprocessing.missing_values import clean_numeric, clean_string
from training.preprocessing.protocol_normalizer import normalize_protocol
from training.preprocessing.validation import validate_flow_record


class TonIoTLoader(BaseDatasetLoader):
    """Loader for TON_IoT Network Flow CSV dataset."""

    def __init__(self, data_path: Path | str):
        super().__init__(data_path, name="ton_iot")

    def inspect_schema(self) -> Dict[str, Any]:
        """Inspects CSV header to confirm network-flow structure."""
        if not self.data_path.exists():
            raise FileNotFoundError(f"File not found: {self.data_path}")

        df_head = pd.read_csv(self.data_path, nrows=2)
        columns = list(df_head.columns)

        # Distinguish network flow from telemetry/OS datasets
        is_network = any(col.lower() in ("src_ip", "dst_ip", "proto", "conn_state") for col in columns)

        return {
            "dataset_name": self.name,
            "format": "csv",
            "is_network_dataset": is_network,
            "columns": columns,
            "column_count": len(columns),
            "sample_types": df_head["type"].tolist() if "type" in df_head.columns else [],
        }

    def load_chunks(
        self, chunk_size: int = 10000, limit: Optional[int] = None
    ) -> Iterator[List[StandardRecord]]:
        """Processes the TON_IoT network CSV in chunks."""
        if not self.data_path.exists():
            raise FileNotFoundError(f"File not found: {self.data_path}")

        csv_iterator = pd.read_csv(self.data_path, chunksize=chunk_size, low_memory=False)

        for df_chunk in csv_iterator:
            self.stats["total_rows"] += len(df_chunk)

            # Strip column whitespace
            df_chunk.columns = [c.strip() for c in df_chunk.columns]
            col_map = {c.lower(): c for c in df_chunk.columns}

            chunk_records: List[StandardRecord] = []
            for _, row in df_chunk.iterrows():
                row_dict = row.to_dict()

                raw_label = str(row_dict.get("type", row_dict.get("label", "normal")))
                norm_res = label_normalizer.normalize(raw_label, dataset_name="ton_iot")

                src_ip = clean_string(row_dict.get("src_ip"), default="192.168.1.1")
                dst_ip = clean_string(row_dict.get("dst_ip"), default="192.168.1.2")

                rec = StandardRecord(
                    timestamp=clean_numeric(row_dict.get("ts"), default=0.0, target_type=float),
                    source_ip=src_ip,
                    destination_ip=dst_ip,
                    source_port=clean_numeric(row_dict.get("src_port"), default=0, target_type=int),
                    destination_port=clean_numeric(row_dict.get("dst_port"), default=0, target_type=int),
                    protocol=normalize_protocol(row_dict.get("proto")),
                    duration=max(0.0, clean_numeric(row_dict.get("duration"), default=0.0, target_type=float)),
                    source_bytes=max(0, clean_numeric(row_dict.get("src_bytes"), default=0, target_type=int)),
                    destination_bytes=max(0, clean_numeric(row_dict.get("dst_bytes"), default=0, target_type=int)),
                    source_packets=max(0, clean_numeric(row_dict.get("src_pkts"), default=0, target_type=int)),
                    destination_packets=max(0, clean_numeric(row_dict.get("dst_pkts"), default=0, target_type=int)),
                    connection_state=clean_string(row_dict.get("conn_state"), default="SF").upper(),
                    source_device_id=f"ton-{src_ip}",
                    destination_device_id=f"ext-{dst_ip}",
                    capture_id="ton_iot_network",
                    scenario_id=norm_res.attack_category,
                    original_label=norm_res.original_label,
                    normalized_label=norm_res.normalized_label.value,
                    dataset_name=self.name,
                    extra_features=row_dict,
                )

                is_valid, _ = validate_flow_record(rec)
                if not is_valid:
                    self.stats["rejected_rows"] += 1
                    continue

                self.stats["valid_rows"] += 1
                chunk_records.append(rec)

                if limit and self.stats["valid_rows"] >= limit:
                    yield chunk_records
                    return

            if chunk_records:
                yield chunk_records
