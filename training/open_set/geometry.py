"""
Feature-Space Geometry & Novelty Measurement Module.

Computes class centroids, class bounding radii, and minimum distance metrics
to detect out-of-distribution (OOD) attack samples in normalized feature space.
"""

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple
import numpy as np


@dataclass
class CentroidGeometry:
    """
    Maintains class centroids and radii in scaled feature space.
    """
    class_names: List[str]
    centroids: Dict[str, np.ndarray]       # class -> centroid vector in R^D
    radii_95: Dict[str, float]             # class -> 95th percentile distance
    global_centroid: np.ndarray
    global_radius_95: float

    @classmethod
    def fit(
        cls,
        X_scaled: np.ndarray,
        y_labels: np.ndarray,
        class_names: List[str],
        percentile: float = 95.0,
    ) -> "CentroidGeometry":
        """Fits centroids and bounding radii from scaled training data."""
        X = np.asarray(X_scaled, dtype=np.float64)
        y = np.asarray(y_labels)

        centroids = {}
        radii = {}

        for c in class_names:
            mask = y == c
            if np.any(mask):
                pts = X[mask]
                center = np.mean(pts, axis=0)
                centroids[c] = center
                dists = np.linalg.norm(pts - center, axis=1)
                radii[c] = float(np.percentile(dists, percentile)) if len(dists) > 0 else 1.0
            else:
                centroids[c] = np.zeros(X.shape[1], dtype=np.float64)
                radii[c] = 1.0

        global_center = np.mean(X, axis=0)
        global_dists = np.linalg.norm(X - global_center, axis=1)
        global_r = float(np.percentile(global_dists, percentile)) if len(global_dists) > 0 else 1.0

        return cls(
            class_names=class_names,
            centroids=centroids,
            radii_95=radii,
            global_centroid=global_center,
            global_radius_95=global_r,
        )

    def distance_to_class(self, x_s: np.ndarray, class_name: str) -> Tuple[float, float]:
        """Returns (raw_distance, normalized_ratio_to_class_radius) for a given class."""
        x = np.asarray(x_s, dtype=np.float64).flatten()
        center = self.centroids.get(class_name, self.global_centroid)
        r = self.radii_95.get(class_name, self.global_radius_95)
        d = float(np.linalg.norm(x - center))
        ratio = d / max(r, 1e-6)
        return round(d, 4), round(ratio, 4)

    def compute_novelty(self, x_s: np.ndarray) -> Dict[str, Any]:
        """
        Computes distance metrics from sample x_s (1D array) to class centroids.
        Returns closest class, distance, normalized novelty ratio, and OOD flag.
        """
        x = np.asarray(x_s, dtype=np.float64).flatten()
        dists = {}
        normalized_ratios = {}

        for c, center in self.centroids.items():
            d = float(np.linalg.norm(x - center))
            dists[c] = d
            r = self.radii_95.get(c, 1.0)
            normalized_ratios[c] = d / max(r, 1e-6)

        closest_class = min(dists.keys(), key=lambda k: dists[k])
        min_dist = dists[closest_class]
        min_ratio = normalized_ratios[closest_class]

        # Novelty score: ratio of distance to closest centroid's 95th percentile radius
        # min_ratio > 1.0 means the point is farther than 95% of training samples for that class
        is_ood = bool(min_ratio > 1.25)

        return {
            "closest_class": closest_class,
            "min_distance": round(min_dist, 4),
            "novelty_score": round(min_ratio, 4),
            "is_geometric_ood": is_ood,
            "class_distances": {k: round(v, 4) for k, v in dists.items()},
        }

    def to_dict(self) -> Dict[str, Any]:
        """Serializes centroids and radii for metadata persistence."""
        return {
            "class_names": self.class_names,
            "radii_95": self.radii_95,
            "global_radius_95": self.global_radius_95,
            "centroids": {k: v.tolist() for k, v in self.centroids.items()},
        }
