"""
IoT-23 Dataset Loader.

Loads Zeek conn.log / conn.log.labeled from the Stratosphere IPS IoT-23 dataset.
Supports both standard Zeek tab-delimited text logs and JSON-lines exports.
"""

import json
from pathlib import Path
from typing import Any, Dict, Iterator, List, Optional

from training.datasets.base_loader import BaseDatasetLoader
from training.feature_contract import StandardRecord
from training.preprocessing.label_normalizer import label_normalizer
from training.preprocessing.missing_values import clean_numeric, clean_string
from training.preprocessing.protocol_normalizer import normalize_protocol
from training.preprocessing.validation import validate_flow_record


class IoT23Loader(BaseDatasetLoader):
    """Loader for Stratosphere IPS IoT-23 captures."""

    def __init__(self, data_path: Path | str, scenario_id: Optional[str] = None):
        super().__init__(data_path, name="iot23")
        self.scenario_id = scenario_id or self._infer_scenario_id(self.data_path)

    def _infer_scenario_id(self, path: Path) -> str:
        # e.g. CTU-IoT-Malware-Capture-34-1
        p_str = str(path)
        for part in Path(p_str).parts:
            if "ctu-iot" in part.lower() or "capture" in part.lower():
                return part
        return path.stem

    def inspect_schema(self) -> Dict[str, Any]:
        """Inspects first non-comment line or JSON object to identify headers."""
        if not self.data_path.exists():
            raise FileNotFoundError(f"Dataset path does not exist: {self.data_path}")

        headers: List[str] = []
        is_json = False

        with open(self.data_path, "r", encoding="utf-8", errors="replace") as f:
            for line in f:
                line_s = line.strip()
                if not line_s:
                    continue
                if line_s.startswith("{"):
                    is_json = True
                    try:
                        d = json.loads(line_s)
                        headers = list(d.keys())
                        break
                    except json.JSONDecodeError:
                        pass
                elif line_s.startswith("#fields"):
                    parts = line_s.split()[1:]
                    headers = parts
                    break
                elif not line_s.startswith("#"):
                    # Tab separated without header
                    headers = [f"col_{i}" for i in range(len(line_s.split("\t")))]
                    break

        return {
            "dataset_name": self.name,
            "format": "json_lines" if is_json else "zeek_tsv",
            "columns": headers,
            "column_count": len(headers),
            "scenario_id": self.scenario_id,
        }

    def load_chunks(
        self, chunk_size: int = 10000, limit: Optional[int] = None
    ) -> Iterator[List[StandardRecord]]:
        """Streams StandardRecord instances in memory-safe chunks."""
        if not self.data_path.exists():
            raise FileNotFoundError(f"File not found: {self.data_path}")

        current_chunk: List[StandardRecord] = []
        headers: List[str] = []
        is_json = False
        seen_keys = set()

        with open(self.data_path, "r", encoding="utf-8", errors="replace") as f:
            for line in f:
                line_s = line.strip()
                if not line_s:
                    continue

                if line_s.startswith("#fields"):
                    headers = line_s.split()[1:]
                    continue
                if line_s.startswith("#"):
                    continue

                self.stats["total_rows"] += 1
                record: Optional[StandardRecord] = None

                if line_s.startswith("{"):
                    is_json = True
                    try:
                        d = json.loads(line_s)
                        record = self._parse_json_dict(d)
                    except json.JSONDecodeError:
                        self.stats["rejected_rows"] += 1
                        continue
                else:
                    parts = line.rstrip("\r\n").split("\t")
                    if headers and len(parts) >= len(headers):
                        d = dict(zip(headers, parts))
                    else:
                        d = self._parse_positional_tsv(parts)
                    record = self._parse_tsv_dict(d)

                if record is None:
                    self.stats["rejected_rows"] += 1
                    continue

                # Validation check
                is_valid, _ = validate_flow_record(record)
                if not is_valid:
                    self.stats["rejected_rows"] += 1
                    continue

                # Duplicate detection by 5-tuple + ts
                flow_sig = (record.timestamp, record.source_ip, record.destination_ip, record.source_port, record.destination_port)
                if flow_sig in seen_keys:
                    self.stats["duplicate_records"] += 1
                seen_keys.add(flow_sig)

                self.stats["valid_rows"] += 1
                current_chunk.append(record)

                if len(current_chunk) >= chunk_size:
                    yield current_chunk
                    current_chunk = []

                if limit and self.stats["valid_rows"] >= limit:
                    break

        if current_chunk:
            yield current_chunk

    def _parse_positional_tsv(self, parts: List[str]) -> Dict[str, str]:
        # Fallback for standard Zeek conn.log order
        fields = [
            "ts", "uid", "id.orig_h", "id.orig_p", "id.resp_h", "id.resp_p",
            "proto", "service", "duration", "orig_bytes", "resp_bytes",
            "conn_state", "local_orig", "local_resp", "missed_bytes", "history",
            "orig_pkts", "orig_ip_bytes", "resp_pkts", "resp_ip_bytes", "tunnel_parents"
        ]
        d = dict(zip(fields, parts[:len(fields)]))
        if len(parts) > len(fields):
            d["label"] = parts[len(fields)]
        if len(parts) > len(fields) + 1:
            d["detailed-label"] = parts[len(fields) + 1]
        return d

    def _parse_tsv_dict(self, d: Dict[str, str]) -> Optional[StandardRecord]:
        detailed = d.get("detailed-label")
        if detailed and detailed.strip() not in ("-", "(empty)"):
            raw_label = detailed.strip()
        else:
            raw_label = d.get("label", "Benign").strip()
            if raw_label in ("-", "(empty)"):
                raw_label = "Benign"

        norm_result = label_normalizer.normalize(raw_label, dataset_name="iot23")

        src_ip = clean_string(d.get("id.orig_h", d.get("src_ip")), default="0.0.0.0")
        dst_ip = clean_string(d.get("id.resp_h", d.get("dst_ip")), default="0.0.0.0")

        return StandardRecord(
            timestamp=clean_numeric(d.get("ts"), default=0.0, target_type=float),
            source_ip=src_ip,
            destination_ip=dst_ip,
            source_port=clean_numeric(d.get("id.orig_p", d.get("src_port")), default=0, target_type=int),
            destination_port=clean_numeric(d.get("id.resp_p", d.get("dst_port")), default=0, target_type=int),
            protocol=normalize_protocol(d.get("proto")),
            duration=max(0.0, clean_numeric(d.get("duration"), default=0.0, target_type=float)),
            source_bytes=max(0, clean_numeric(d.get("orig_bytes"), default=0, target_type=int)),
            destination_bytes=max(0, clean_numeric(d.get("resp_bytes"), default=0, target_type=int)),
            source_packets=max(0, clean_numeric(d.get("orig_pkts"), default=0, target_type=int)),
            destination_packets=max(0, clean_numeric(d.get("resp_pkts"), default=0, target_type=int)),
            connection_state=clean_string(d.get("conn_state"), default="SF").upper(),
            source_device_id=f"iot23-{src_ip}",
            destination_device_id=f"ext-{dst_ip}",
            capture_id=self.scenario_id,
            scenario_id=self.scenario_id,
            original_label=norm_result.original_label,
            normalized_label=norm_result.normalized_label.value,
            dataset_name=self.name,
        )

    def _parse_json_dict(self, d: Dict[str, Any]) -> Optional[StandardRecord]:
        return self._parse_tsv_dict({k: str(v) for k, v in d.items()})
