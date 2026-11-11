"""
Unit tests for Feature-Space Centroid Geometry (training/open_set/geometry.py).
"""

import numpy as np
import pytest
from training.open_set.geometry import CentroidGeometry


def test_centroid_geometry_in_bounds_and_ood():
    np.random.seed(42)
    # Class A: cluster around (0, 0)
    pts_a = np.random.normal(loc=0.0, scale=1.0, size=(100, 2))
    # Class B: cluster around (10, 10)
    pts_b = np.random.normal(loc=10.0, scale=1.0, size=(100, 2))

    X = np.vstack([pts_a, pts_b])
    y = np.array(["class_a"] * 100 + ["class_b"] * 100)

    geom = CentroidGeometry.fit(X, y, class_names=["class_a", "class_b"], percentile=95.0)

    # 1. In-distribution sample close to Class A center
    in_sample = np.array([0.2, -0.1])
    res_in = geom.compute_novelty(in_sample)
    assert res_in["closest_class"] == "class_a"
    assert res_in["is_geometric_ood"] is False
    assert res_in["novelty_score"] < 1.0

    # 2. Out-of-distribution sample far from both clusters (e.g. at 50, 50)
    ood_sample = np.array([50.0, 50.0])
    res_ood = geom.compute_novelty(ood_sample)
    assert res_ood["is_geometric_ood"] is True
    assert res_ood["novelty_score"] > 2.0

    # 3. Class-specific distance check
    dist_a, ratio_a = geom.distance_to_class(in_sample, "class_a")
    assert dist_a < 1.0
    assert ratio_a < 1.0

    # 4. Serialization dictionary
    d = geom.to_dict()
    assert "class_names" in d
    assert "centroids" in d
    assert "radii_95" in d
