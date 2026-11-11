"""
Command-Line Interface for Dataset Inspection, Validation, and Ingestion.

Usage:
  py -3.14 -m training.datasets inspect --dataset iot23 --path path/to/conn.log
  py -3.14 -m training.datasets validate --dataset ciciot2023 --path path/to/file.csv
  py -3.14 -m training.datasets report --dataset ton_iot --path path/to/file.csv
  py -3.14 -m training.datasets prepare --dataset iot23 --path path/to/conn.log --limit 1000
"""

import argparse
import json
import sys
from pathlib import Path

# Add project root to path
PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from training.datasets.registry import get_dataset_loader, list_supported_datasets
from training.evaluation.dataset_report import generate_dataset_report
from training.splitting.chronological_split import chronological_split
from training.splitting.leakage_detection import check_leakage


def main():
    parser = argparse.ArgumentParser(
        prog="training.datasets",
        description="Pahredaar-IoT Dataset Tooling CLI",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    # 1. Inspect
    inspect_parser = subparsers.add_parser("inspect", help="Inspect dataset headers and column structure")
    inspect_parser.add_argument("--dataset", required=True, choices=list_supported_datasets(), help="Dataset name")
    inspect_parser.add_argument("--path", required=True, help="Path to dataset file")

    # 2. Validate
    validate_parser = subparsers.add_parser("validate", help="Validate schema and load sample records")
    validate_parser.add_argument("--dataset", required=True, choices=list_supported_datasets())
    validate_parser.add_argument("--path", required=True)
    validate_parser.add_argument("--limit", type=int, default=1000, help="Number of records to validate")

    # 3. Report
    report_parser = subparsers.add_parser("report", help="Generate full JSON/Markdown dataset audit report")
    report_parser.add_argument("--dataset", required=True, choices=list_supported_datasets())
    report_parser.add_argument("--path", required=True)
    report_parser.add_argument("--limit", type=int, default=5000)
    report_parser.add_argument("--output-dir", default="reports/datasets")

    # 4. Prepare
    prepare_parser = subparsers.add_parser("prepare", help="Load and prepare chronological train/val/test splits")
    prepare_parser.add_argument("--dataset", required=True, choices=list_supported_datasets())
    prepare_parser.add_argument("--path", required=True)
    prepare_parser.add_argument("--limit", type=int, default=5000)

    args = parser.parse_args()
    data_path = Path(args.path)

    if not data_path.exists():
        print(f"[ERROR] Target file does not exist: {data_path}", file=sys.stderr)
        sys.exit(1)

    loader = get_dataset_loader(args.dataset, data_path)

    if args.command == "inspect":
        schema = loader.inspect_schema()
        print(json.dumps(schema, indent=2))

    elif args.command == "validate":
        print(f"Validating dataset '{args.dataset}' from '{data_path}' (limit: {args.limit})...")
        records = loader.load_all(limit=args.limit)
        summary = loader.get_summary()
        print(f"[SUCCESS] Loaded {len(records)} valid records.")
        print(json.dumps(summary, indent=2))

    elif args.command == "report":
        print(f"Generating audit report for '{args.dataset}' (limit: {args.limit})...")
        records = loader.load_all(limit=args.limit)
        report = generate_dataset_report(
            dataset_name=args.dataset,
            records=records,
            source_path=str(data_path),
            output_dir=args.output_dir,
            extra_metadata=loader.get_summary(),
        )
        print(f"[SUCCESS] Report written to '{args.output_dir}/{args.dataset}_report.md'")
        print(f"Total: {report['total_records']}, Compatibility: {report['feature_compatibility']['compatibility_percentage']}%")

    elif args.command == "prepare":
        print(f"Loading and splitting '{args.dataset}'...")
        records = loader.load_all(limit=args.limit)
        split = chronological_split(records, train_ratio=0.70, val_ratio=0.15, test_ratio=0.15)
        leakage = check_leakage(split.train, split.test)
        print(f"[SPLIT COMPLETE] Train: {len(split.train)}, Val: {len(split.val)}, Test: {len(split.test)}")
        print(f"[LEAKAGE AUDIT] Clean: {leakage.is_leakage_free}, Overlapping flows: {leakage.duplicate_flow_count}")


if __name__ == "__main__":
    main()
