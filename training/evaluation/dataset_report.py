"""
Dataset Reporting Module.

Generates structured JSON and Markdown audit reports for loaded datasets.
"""

from datetime import datetime, timezone
import json
from pathlib import Path
from typing import Any, Dict, List, Optional

from training.evaluation.class_distribution import compute_class_distribution
from training.feature_contract import StandardRecord, canonical_contract


def generate_dataset_report(
    dataset_name: str,
    records: List[StandardRecord],
    source_path: str,
    output_dir: Path | str = "reports/datasets",
    extra_metadata: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """
    Analyzes records and outputs formatted JSON and Markdown reports.
    """
    out_dir = Path(output_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    dist = compute_class_distribution(records)

    # Time bounds
    if records:
        min_ts = min(r.timestamp for r in records)
        max_ts = max(r.timestamp for r in records)
        duration_hours = round((max_ts - min_ts) / 3600.0, 2)
    else:
        min_ts = max_ts = duration_hours = 0.0

    # Collect sample columns if extra features exist
    sample_cols = list(records[0].extra_features.keys()) if records and records[0].extra_features else [
        "timestamp", "source_ip", "destination_ip", "source_port", "destination_port",
        "protocol", "duration", "source_bytes", "destination_bytes", "source_packets",
        "destination_packets", "connection_state", "normalized_label"
    ]

    compat = canonical_contract.evaluate_dataset_compatibility(sample_cols)

    report_data = {
        "dataset_name": dataset_name,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "source_path": str(source_path),
        "total_records": len(records),
        "time_range": {
            "start_ts": min_ts,
            "end_ts": max_ts,
            "duration_hours": duration_hours,
        },
        "class_distribution": {
            "counts": dist.class_counts,
            "percentages": dist.class_percentages,
            "imbalance_ratio": dist.imbalance_ratio,
            "shannon_entropy": dist.shannon_entropy,
        },
        "feature_compatibility": compat,
        "metadata": extra_metadata or {},
    }

    # Save JSON report
    json_path = out_dir / f"{dataset_name}_report.json"
    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(report_data, f, indent=2)

    # Save Markdown report
    md_path = out_dir / f"{dataset_name}_report.md"
    with open(md_path, "w", encoding="utf-8") as f:
        f.write(f"# Dataset Audit Report: {dataset_name.upper()}\n\n")
        f.write(f"- **Generated At:** {report_data['generated_at']}\n")
        f.write(f"- **Source:** `{source_path}`\n")
        f.write(f"- **Total Flow Records:** {len(records):,}\n")
        f.write(f"- **Capture Span:** {duration_hours} hours (`{min_ts}` to `{max_ts}`)\n\n")

        f.write("## 1. Class Distribution\n\n")
        f.write("| Normalized Class | Flow Count | Percentage |\n")
        f.write("|---|---|---|\n")
        for cls, count in dist.class_counts.items():
            pct = dist.class_percentages.get(cls, 0.0)
            f.write(f"| `{cls}` | {count:,} | {pct}% |\n")
        f.write(f"\n- **Class Imbalance Ratio:** {dist.imbalance_ratio}:1\n")
        f.write(f"- **Shannon Diversity Entropy:** {dist.shannon_entropy} bits\n\n")

        f.write("## 2. Feature Compatibility vs. Canonical Contract (V1)\n\n")
        f.write(f"- **Compatibility Score:** {compat['compatibility_percentage']}%\n")
        f.write(f"- **Fully Compatible:** {'✅ YES' if compat['is_fully_compatible'] else '⚠️ PARTIAL'}\n\n")
        f.write("### Breakdown:\n")
        for category, items in compat["breakdown"].items():
            if items:
                f.write(f"- **{category.replace('_', ' ').title()} ({len(items)}):** {', '.join(items.keys())}\n")

    return report_data
