"""
Edge-IIoTset Dataset Loader.

Loads the IEEE Edge-IIoTset Cyber Security Dataset (Ferrag et al., 2022).
Maps raw Edge-IIoTset flow records to StandardRecord instances with validated label normalization.
Supports both IoT/IIoT protocol traffic (MQTT, CoAP, Modbus, HTTP) and 14 distinct attack classes.
"""

from pathlib import Path
from typing import Any, Dict, Iterator, List, Optional
import pandas as pd

from training.datasets.base_loader import BaseDatasetLoader
from training.feature_contract import StandardRecord
from training.preprocessing.label_normalizer import label_normalizer
from training.preprocessing.missing_values import clean_numeric, clean_string
from training.preprocessing.protocol_normalizer import normalize_protocol


class EdgeIIoTsetLoader(BaseDatasetLoader):
    """Loader for Edge-IIoTset CSV dataset (IEEE Access 2022)."""

    def __init__(self, data_path: Path | str):
        super().__init__(data_path, name="edge_iiotset")

    def inspect_schema(self) -> Dict[str, Any]:
        """Inspects CSV header to confirm Edge-IIoTset structure."""
        if not self.data_path.exists():
            raise FileNotFoundError(f"File not found: {self.data_path}")

        df_head = pd.read_csv(self.data_path, nrows=2)
        columns = [c.strip() for c in df_head.columns]

        is_edge_iiot = any(
            c.lower() in ("attack_type", "attack_label", "frame.time", "tcp.flags", "mqtt.msgtype")
            for c in columns
        )

        return {
            "dataset_name": self.name,
            "format": "csv",
            "is_edge_iiotset": is_edge_iiot,
            "columns": columns,
            "column_count": len(columns),
            "sample_attack_types": df_head["Attack_type"].tolist() if "Attack_type" in df_head.columns else [],
        }

    def load_chunks(
        self, chunk_size: int = 10000, limit: Optional[int] = None
    ) -> Iterator[List[StandardRecord]]:
        """Processes the Edge-IIoTset CSV in streaming chunks."""
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

                raw_label = clean_string(
                    row_dict.get("attack_type", row_dict.get("attack_label", "Normal")),
                    default="Normal",
                )

                norm_res = label_normalizer.normalize(raw_label, dataset_name="edge_iiotset")

                src_ip = clean_string(row_dict.get("ip.src_host", row_dict.get("src_ip")), default="192.168.1.100")
                dst_ip = clean_string(row_dict.get("ip.dst_host", row_dict.get("dst_ip")), default="192.168.1.1")

                # Parse protocols and ports
                proto_raw = row_dict.get("ip.proto", row_dict.get("protocol", "tcp"))
                sport = clean_numeric(row_dict.get("tcp.srcport", row_dict.get("udp.srcport")), default=0, target_type=int)
                dport = clean_numeric(row_dict.get("tcp.dstport", row_dict.get("udp.dstport")), default=0, target_type=int)

                # Packet lengths / byte aggregates
                payload_len = clean_numeric(row_dict.get("tcp.len", row_dict.get("udp.length")), default=64, target_type=int)
                frame_len = clean_numeric(row_dict.get("frame.len"), default=max(payload_len, 64), target_type=int)

                rec = StandardRecord(
                    timestamp=clean_numeric(row_dict.get("frame.time_epoch", row_dict.get("timestamp")), default=0.0, target_type=float),
                    source_ip=src_ip,
                    destination_ip=dst_ip,
                    source_port=sport,
                    destination_port=dport,
                    protocol=normalize_protocol(proto_raw),
                    duration=clean_numeric(row_dict.get("flow_duration", row_dict.get("tcp.time_delta")), default=0.0, target_type=float),
                    source_bytes=frame_len,
                    destination_bytes=0,
                    source_packets=1,
                    destination_packets=0,
                    connection_state=clean_string(row_dict.get("tcp.flags"), default="ACK").upper(),
                    source_device_id=f"edge-{src_ip}",
                    destination_device_id=f"host-{dst_ip}",
                    capture_id="edge_iiotset_2022",
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
