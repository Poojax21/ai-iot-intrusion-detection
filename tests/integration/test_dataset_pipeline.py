"""
Integration test for dataset loader pipeline, report generation, and CLI.
"""

from pathlib import Path
from training.datasets.registry import get_dataset_loader
from training.evaluation.dataset_report import generate_dataset_report

FIXTURE_IOT23 = Path("tests/fixtures/sample_iot23.log")


def test_full_dataset_pipeline_iot23(tmp_path):
    loader = get_dataset_loader("iot23", FIXTURE_IOT23)
    records = loader.load_all()
    assert len(records) == 6

    # Generate report
    rep = generate_dataset_report(
        dataset_name="test_iot23",
        records=records,
        source_path=str(FIXTURE_IOT23),
        output_dir=tmp_path / "reports",
    )
    assert rep["total_records"] == 6
    assert (tmp_path / "reports" / "test_iot23_report.json").exists()
    assert (tmp_path / "reports" / "test_iot23_report.md").exists()
