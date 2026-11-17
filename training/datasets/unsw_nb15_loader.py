"""
UNSW-NB15 Dataset Loader.

Loads the canonical UNSW-NB15 intrusion detection dataset (Moustafa & Slay, 2015).
Maps raw UNSW-NB15 network flow records (49 features) to StandardRecord instances.
Supports 9 distinct attack categories: Fuzzers, Analysis, Backdoors, DoS, Exploits,
Generic, Reconnaissance, Shellcode, and Worms.
"""

from pathlib import Path
from typing import Any, Dict, Iterator, List, Optional
import pandas as pd

from training.datasets.base_loader import BaseDatasetLoader
from training.feature_contract import StandardRecord
from training.preprocessing.label_normalizer import label_normalizer
from training.preprocessing.missing_values import clean_numeric, clean_string
from training.preprocessing.protocol_normalizer import normalize_protocol


class UNSWNB15Loader(BaseDatasetLoader):
    """Loader for UNSW-NB15 CSV dataset (UNSW Canberra Cyber)."""

    def __init__(self, data_path: Path | str):
        super().__init__(data_path, name="unsw_nb15")

    def inspect_schema(self) -> Dict[str, Any]:
        """Inspects CSV header to confirm UNSW-NB15 structure."""
        if not self.data_path.exists():
            raise FileNotFoundError(f"File not found: {self.data_path}")

        df_head = pd.read_csv(self.data_path, nrows=2)
        columns = [c.strip() for c in df_head.columns]

        is_unsw = any(
            c.lower() in ("attack_cat", "sbytes", "dbytes", "sttl", "dttl", "sloss")
            for c in columns
        )

        return {
            "dataset_name": self.name,
            "format": "csv",
            "is_unsw_nb15": is_unsw,
            "columns": columns,
            "column_count": len(columns),
            "sample_categories": df_head["attack_cat"].tolist() if "attack_cat" in df_head.columns else [],
        }

    def load_chunks(
        self, chunk_size: int = 10000, limit: Optional[int] = None
    ) -> Iterator[List[StandardRecord]]:
        """Processes the UNSW-NB15 CSV in streaming chunks."""
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

                attack_cat = clean_string(row_dict.get("attack_cat"), default="")
                label_val = clean_numeric(row_dict.get("label"), default=0, target_type=int)

                if attack_cat and attack_cat.lower() not in ("normal", "benign", "-"):
                    raw_label = attack_cat
                elif label_val == 0:
                    raw_label = "normal"
                else:
                    raw_label = "attack"

                norm_res = label_normalizer.normalize(raw_label, dataset_name="unsw_nb15")

                src_ip = clean_string(row_dict.get("srcip", row_dict.get("saddr")), default="172.16.0.1")
                dst_ip = clean_string(row_dict.get("dstip", row_dict.get("daddr")), default="192.168.1.1")

                rec = StandardRecord(
                    timestamp=clean_numeric(row_dict.get("stime", row_dict.get("ltime")), default=0.0, target_type=float),
                    source_ip=src_ip,
                    destination_ip=dst_ip,
                    source_port=clean_numeric(row_dict.get("sport"), default=0, target_type=int),
                    destination_port=clean_numeric(row_dict.get("dsport", row_dict.get("dport")), default=0, target_type=int),
                    protocol=normalize_protocol(row_dict.get("proto")),
                    duration=max(0.0, clean_numeric(row_dict.get("dur"), default=0.0, target_type=float)),
                    source_bytes=max(0, clean_numeric(row_dict.get("sbytes"), default=64, target_type=int)),
                    destination_bytes=max(0, clean_numeric(row_dict.get("dbytes"), default=0, target_type=int)),
                    source_packets=max(0, clean_numeric(row_dict.get("spkts"), default=1, target_type=int)),
                    destination_packets=max(0, clean_numeric(row_dict.get("dpkts"), default=0, target_type=int)),
                    connection_state=clean_string(row_dict.get("state"), default="FIN").upper(),
                    source_device_id=f"unsw-{src_ip}",
                    destination_device_id=f"host-{dst_ip}",
                    capture_id="unsw_nb15",
                    scenario_id=norm_res.attack_category,
                    original_label=norm_res.original_label,
                    normalized_label=norm_res.normalized_label.value,
                    attack_category=norm_res.attack_category,
                    is_attack=norm_res.is_attack,
                )
                chunk_records.append(rec)

                if limit and len(chunk_records) >= limit:
                    break

            self.stats["valid_records"] += len(chunk_records)
            yield chunk_records

            if limit and self.stats["valid_records"] >= limit:
                break
