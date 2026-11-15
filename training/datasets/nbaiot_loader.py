"""
N-BaIoT Dataset Loader.

Loads the UCI N-BaIoT dataset (Network-based Anomaly Detection in IoT).
Supports both single pre-tagged CSV files and directory structures containing
per-device/per-attack traffic captures (Danmini Doorbell, Ecobee, cameras, etc.).
"""

from pathlib import Path
from typing import Any, Dict, Iterator, List, Optional
import os
import pandas as pd

from training.datasets.base_loader import BaseDatasetLoader
from training.feature_contract import StandardRecord
from training.preprocessing.label_normalizer import label_normalizer
from training.preprocessing.missing_values import clean_numeric, clean_string
from training.preprocessing.protocol_normalizer import normalize_protocol
from training.preprocessing.validation import validate_flow_record


class NBaIoTLoader(BaseDatasetLoader):
    """Loader for UCI N-BaIoT dataset (115 streaming statistical features)."""

    def __init__(self, data_path: Path | str):
        super().__init__(data_path, name="nbaiot")

    def _infer_label_from_path(self, path: Path) -> str:
        """Infers attack or benign label from filename or folder."""
        stem = path.stem.lower()
        parts = [p.lower() for p in path.parts]

        if "benign" in stem or "benign" in parts:
            return "benign"
        if "scan" in stem:
            return "mirai_scan" if "mirai" in stem else "gafgyt_scan"
        if "syn" in stem:
            return "mirai_syn"
        if "ack" in stem:
            return "mirai_ack"
        if "udp" in stem:
            return "mirai_udp"
        if "combo" in stem:
            return "gafgyt_combo"
        if "junk" in stem:
            return "gafgyt_junk"
        if "mirai" in stem or "mirai" in parts:
            return "mirai"
        if "gafgyt" in stem or "gafgyt" in parts:
            return "gafgyt"
        return "attack"

    def _infer_device_from_path(self, path: Path) -> str:
        """Extracts device name from filename or parent directory."""
        stem = path.stem
        # Check known devices
        for dev in ("Danmini_Doorbell", "Ecobee_Thermostat", "Ennio_Doorbell",
                    "Philips_B120N10_Baby_Monitor", "Provision_PT_737E",
                    "Provision_PT_838", "SimpleHome_XCS7_1002",
                    "SimpleHome_XCS7_1003", "Samsung_SNH_1011_N"):
            if dev.lower() in str(path).lower():
                return dev
        return stem.split(".")[0] if "." in stem else "iot_device"

    def inspect_schema(self) -> Dict[str, Any]:
        """Inspects CSV header to confirm N-BaIoT structure."""
        if not self.data_path.exists():
            raise FileNotFoundError(f"Path not found: {self.data_path}")

        csv_file = self.data_path
        if self.data_path.is_dir():
            csv_files = list(self.data_path.rglob("*.csv"))
            if not csv_files:
                raise FileNotFoundError(f"No CSV files found in {self.data_path}")
            csv_file = csv_files[0]

        df_head = pd.read_csv(csv_file, nrows=2)
        columns = [c.strip() for c in df_head.columns]

        is_nbaiot = any("mi_dir" in c.lower() or "h_l" in c.lower() or "hh_l" in c.lower() for c in columns)

        return {
            "dataset_name": self.name,
            "format": "csv",
            "is_nbaiot": is_nbaiot,
            "columns": columns[:20],
            "column_count": len(columns),
            "sample_file": str(csv_file.name),
        }

    def load_chunks(
        self, chunk_size: int = 10000, limit: Optional[int] = None
    ) -> Iterator[List[StandardRecord]]:
        """Processes N-BaIoT CSV(s) in streaming chunks."""
        if not self.data_path.exists():
            raise FileNotFoundError(f"Path not found: {self.data_path}")

        files = [self.data_path] if self.data_path.is_file() else sorted(list(self.data_path.rglob("*.csv")))

        for file_path in files:
            default_label = self._infer_label_from_path(file_path)
            device_name = self._infer_device_from_path(file_path)

            csv_iterator = pd.read_csv(file_path, chunksize=chunk_size, low_memory=False)

            for df_chunk in csv_iterator:
                self.stats["total_rows"] += len(df_chunk)
                df_chunk.columns = [c.strip() for c in df_chunk.columns]

                chunk_records: List[StandardRecord] = []
                for idx, row in df_chunk.iterrows():
                    row_dict = row.to_dict()

                    raw_label = str(row_dict.get("label", row_dict.get("type", default_label)))
                    norm_res = label_normalizer.normalize(raw_label, dataset_name="nbaiot")

                    # Extract weights or packet rates if available
                    weight = clean_numeric(row_dict.get("MI_dir_L5_weight", row_dict.get("H_L5_weight")), default=1.0, target_type=float)
                    sbytes = int(clean_numeric(row_dict.get("MI_dir_L5_mean", 64.0), default=64.0, target_type=float) * max(1.0, weight))

                    ts = clean_numeric(row_dict.get("timestamp", row_dict.get("ts")), default=float(self.stats["total_rows"]), target_type=float)

                    rec = StandardRecord(
                        timestamp=ts,
                        source_ip=clean_string(row_dict.get("src_ip"), default="192.168.1.50"),
                        destination_ip=clean_string(row_dict.get("dst_ip"), default="192.168.1.1"),
                        source_port=clean_numeric(row_dict.get("src_port"), default=0, target_type=int),
                        destination_port=clean_numeric(row_dict.get("dst_port"), default=0, target_type=int),
                        protocol=normalize_protocol(row_dict.get("proto", "tcp")),
                        duration=max(0.0, clean_numeric(row_dict.get("dur", 0.0), default=0.0, target_type=float)),
                        source_bytes=max(0, sbytes),
                        destination_bytes=0,
                        source_packets=max(1, int(weight)),
                        destination_packets=0,
                        connection_state="SF" if not norm_res.is_attack else "S0",
                        source_device_id=f"nbaiot-{device_name}",
                        destination_device_id="ext-gateway",
                        capture_id=file_path.stem,
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
