"""
Bot-IoT Dataset Loader.

Loads the UNSW Canberra Bot-IoT dataset (5% extract or full CSVs).
Maps raw BoT-IoT flow records to StandardRecord instances with validated label normalization.
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


class BotIoTLoader(BaseDatasetLoader):
    """Loader for Bot-IoT CSV dataset (UNSW Canberra)."""

    def __init__(self, data_path: Path | str):
        super().__init__(data_path, name="bot_iot")

    def inspect_schema(self) -> Dict[str, Any]:
        """Inspects CSV header to confirm Bot-IoT structure."""
        if not self.data_path.exists():
            raise FileNotFoundError(f"File not found: {self.data_path}")

        df_head = pd.read_csv(self.data_path, nrows=2)
        columns = [c.strip() for c in df_head.columns]

        is_bot_iot = any(c.lower() in ("pkseqid", "saddr", "daddr", "category", "subcategory") for c in columns)

        return {
            "dataset_name": self.name,
            "format": "csv",
            "is_bot_iot": is_bot_iot,
            "columns": columns,
            "column_count": len(columns),
            "sample_categories": df_head["category"].tolist() if "category" in df_head.columns else [],
        }

    def load_chunks(
        self, chunk_size: int = 10000, limit: Optional[int] = None
    ) -> Iterator[List[StandardRecord]]:
        """Processes the Bot-IoT CSV in streaming chunks."""
        if not self.data_path.exists():
            raise FileNotFoundError(f"File not found: {self.data_path}")

        csv_iterator = pd.read_csv(self.data_path, chunksize=chunk_size, low_memory=False)

        for df_chunk in csv_iterator:
            self.stats["total_rows"] += len(df_chunk)

            # Normalize column names to lower stripped
            df_chunk.columns = [c.strip().lower() for c in df_chunk.columns]

            chunk_records: List[StandardRecord] = []
            for _, row in df_chunk.iterrows():
                row_dict = row.to_dict()

                category = clean_string(row_dict.get("category"), default="Normal")
                subcategory = clean_string(row_dict.get("subcategory"), default="")
                if subcategory and subcategory.lower() not in ("normal", category.lower()):
                    raw_label = f"{category}_{subcategory}"
                else:
                    raw_label = category

                norm_res = label_normalizer.normalize(raw_label, dataset_name="bot_iot")

                src_ip = clean_string(row_dict.get("saddr"), default="192.168.1.100")
                dst_ip = clean_string(row_dict.get("daddr"), default="192.168.1.1")

                # Derive packets and bytes
                spkts = clean_numeric(row_dict.get("spkts", row_dict.get("pkts")), default=1, target_type=int)
                dpkts = clean_numeric(row_dict.get("dpkts"), default=0, target_type=int)
                sbytes = clean_numeric(row_dict.get("sbytes", row_dict.get("bytes")), default=64, target_type=int)
                dbytes = clean_numeric(row_dict.get("dbytes"), default=0, target_type=int)

                rec = StandardRecord(
                    timestamp=clean_numeric(row_dict.get("stime", row_dict.get("ts")), default=0.0, target_type=float),
                    source_ip=src_ip,
                    destination_ip=dst_ip,
                    source_port=clean_numeric(row_dict.get("sport"), default=0, target_type=int),
                    destination_port=clean_numeric(row_dict.get("dport"), default=0, target_type=int),
                    protocol=normalize_protocol(row_dict.get("proto")),
                    duration=max(0.0, clean_numeric(row_dict.get("dur", row_dict.get("duration")), default=0.0, target_type=float)),
                    source_bytes=max(0, sbytes),
                    destination_bytes=max(0, dbytes),
                    source_packets=max(0, spkts),
                    destination_packets=max(0, dpkts),
                    connection_state=clean_string(row_dict.get("state"), default="CON").upper(),
                    source_device_id=f"botiot-{src_ip}",
                    destination_device_id=f"ext-{dst_ip}",
                    capture_id="bot_iot_unsw",
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
