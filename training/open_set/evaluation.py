"""
Comprehensive Open-Set Evaluation & Benchmark Module.

Evaluates known-class classification, unknown-attack detection rates,
false-positive and false-rejection trade-offs, and inference throughput.
"""

from dataclasses import dataclass, field
import time
from typing import Any, Dict, List, Optional, Tuple
import numpy as np
from sklearn.metrics import classification_report, confusion_matrix, precision_recall_fscore_support, roc_auc_score, average_precision_score

from training.open_set.classifier import OpenSetClassifier, OpenSetDecisionOutcome


@dataclass
class OpenSetEvaluationReport:
    # Known-class metrics
    known_accuracy: float
    known_macro_f1: float
    known_fpr_benign: float
    class_report: Dict[str, Any]

    # Unknown-attack metrics
    unknown_detection_rate: float        # Recall on true unknown attacks
    unknown_precision: float             # Precision when predicting unknown
    false_unknown_rate_benign: float     # False alarm rate on benign (calling benign unknown)
    false_rejection_rate_known: float    # Known attack falsely rejected as unknown
    auroc_novelty: float
    auprc_novelty: float

    # Operational metrics
    mean_latency_ms: float
    throughput_samples_sec: float
    total_test_samples: int
    known_test_samples: int
    unknown_test_samples: int

    # Breakdowns
    confusion_matrix_data: List[List[int]]
    labels_order: List[str]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "known_metrics": {
                "accuracy": round(self.known_accuracy, 4),
                "macro_f1": round(self.known_macro_f1, 4),
                "fpr_on_benign": round(self.known_fpr_benign, 4),
                "per_class": self.class_report,
            },
            "unknown_metrics": {
                "unknown_detection_rate_recall": round(self.unknown_detection_rate, 4),
                "unknown_precision": round(self.unknown_precision, 4),
                "false_unknown_rate_benign": round(self.false_unknown_rate_benign, 4),
                "false_rejection_rate_known": round(self.false_rejection_rate_known, 4),
                "auroc_novelty": round(self.auroc_novelty, 4),
                "auprc_novelty": round(self.auprc_novelty, 4),
            },
            "operational": {
                "mean_latency_ms": round(self.mean_latency_ms, 3),
                "throughput_samples_sec": round(self.throughput_samples_sec, 1),
                "total_samples": self.total_test_samples,
                "known_samples": self.known_test_samples,
                "unknown_samples": self.unknown_test_samples,
            },
        }


def evaluate_open_set_performance(
    classifier: OpenSetClassifier,
    X_test: np.ndarray,
    y_test_labels: List[str],
    known_classes: List[str],
    unknown_classes: List[str],
    feature_names: Optional[List[str]] = None,
) -> OpenSetEvaluationReport:
    """
    Evaluates an OpenSetClassifier on a mixed test partition containing both
    known classes and held-out unknown classes.
    """
    n_samples = len(X_test)
    if n_samples == 0:
        raise ValueError("X_test cannot be empty")

    # Fast vectorized inference over full test split
    decisions = classifier.predict_batch(X_test, feature_names=feature_names)

    # Benchmark single-sample latency over a representative subsample (up to 200 samples)
    n_bench = min(n_samples, 200)
    latencies = []
    for i in range(n_bench):
        t0 = time.perf_counter()
        _ = classifier.predict_sample(X_test[i], feature_names=feature_names)
        t_delta = (time.perf_counter() - t0) * 1000.0  # ms
        latencies.append(t_delta)

    mean_latency = float(np.mean(latencies))
    throughput = 1000.0 / mean_latency if mean_latency > 0 else 0.0

    # Separate predictions and truth
    y_true = np.array(y_test_labels)
    is_true_unknown = np.isin(y_true, unknown_classes)
    is_true_benign = (y_true == "benign") | (y_true == "BENIGN")
    is_true_known_attack = np.isin(y_true, known_classes) & (~is_true_benign)

    is_pred_unknown = np.array([
        (d.outcome in (OpenSetDecisionOutcome.UNKNOWN_SUSPICIOUS, OpenSetDecisionOutcome.UNCERTAIN))
        for d in decisions
    ])

    # 1. Unknown detection rate (Recall on unknown)
    n_true_unknown = int(np.sum(is_true_unknown))
    if n_true_unknown > 0:
        udr = float(np.sum(is_pred_unknown & is_true_unknown)) / float(n_true_unknown)
    else:
        udr = 1.0

    # 2. Unknown precision
    n_pred_unknown = int(np.sum(is_pred_unknown))
    if n_pred_unknown > 0:
        udp = float(np.sum(is_pred_unknown & is_true_unknown)) / float(n_pred_unknown)
    else:
        udp = 1.0

    # 3. False unknown rate on benign (benign called unknown)
    n_benign = int(np.sum(is_true_benign))
    if n_benign > 0:
        fur_benign = float(np.sum(is_pred_unknown & is_true_benign)) / float(n_benign)
    else:
        fur_benign = 0.0

    # 4. False rejection rate on known attack (known attack called unknown)
    n_known_attack = int(np.sum(is_true_known_attack))
    if n_known_attack > 0:
        frr_known = float(np.sum(is_pred_unknown & is_true_known_attack)) / float(n_known_attack)
    else:
        frr_known = 0.0

    # 5. AUROC and AUPRC for novelty score detecting true unknown
    novelty_scores = np.array([d.novelty_score for d in decisions])
    if n_true_unknown > 0 and (n_samples - n_true_unknown) > 0:
        try:
            auroc = float(roc_auc_score(is_true_unknown.astype(int), novelty_scores))
            auprc = float(average_precision_score(is_true_unknown.astype(int), novelty_scores))
        except Exception:
            auroc, auprc = 0.5, 0.5
    else:
        auroc, auprc = 1.0, 1.0

    # 6. Known-class evaluation on known subset only
    known_mask = ~is_true_unknown
    if np.any(known_mask):
        y_true_known = y_true[known_mask]
        y_pred_known = np.array([d.predicted_class or "unknown" for d in np.array(decisions)[known_mask]])

        cls_rep = classification_report(y_true_known, y_pred_known, output_dict=True, zero_division=0)
        p, r, f1, _ = precision_recall_fscore_support(y_true_known, y_pred_known, average="macro", zero_division=0)
        known_macro_f1 = float(f1)
        known_acc = float(np.mean(y_true_known == y_pred_known))

        # Benign FPR on known subset
        benign_submask = is_true_benign[known_mask]
        if np.any(benign_submask):
            fpr_benign = float(np.mean(y_pred_known[benign_submask] != "benign"))
        else:
            fpr_benign = 0.0

        all_known_labels = sorted(list(set(y_true_known).union(set(y_pred_known))))
        cm = confusion_matrix(y_true_known, y_pred_known, labels=all_known_labels).tolist()
    else:
        known_acc, known_macro_f1, fpr_benign = 0.0, 0.0, 0.0
        cls_rep = {}
        cm, all_known_labels = [], []

    return OpenSetEvaluationReport(
        known_accuracy=known_acc,
        known_macro_f1=known_macro_f1,
        known_fpr_benign=fpr_benign,
        class_report=cls_rep,
        unknown_detection_rate=udr,
        unknown_precision=udp,
        false_unknown_rate_benign=fur_benign,
        false_rejection_rate_known=frr_known,
        auroc_novelty=auroc,
        auprc_novelty=auprc,
        mean_latency_ms=mean_latency,
        throughput_samples_sec=throughput,
        total_test_samples=n_samples,
        known_test_samples=int(np.sum(known_mask)),
        unknown_test_samples=n_true_unknown,
        confusion_matrix_data=cm,
        labels_order=all_known_labels,
    )
