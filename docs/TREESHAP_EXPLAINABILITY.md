# Pahredaar-IoT — Exact TreeSHAP Explainability Specification
**Document Version:** 1.0 (Phase 4 Specification)  
**Authors:** Senior Machine Learning Engineer & Lead Data Scientist  

---

## 1. Theory & Mathematical Formulation

Heuristic ablation explanations evaluate feature importance by setting a feature to its baseline (e.g. scaler-mean 0.0) and measuring the difference in output:
$$\text{contrib}_{heuristic}(i) = f(\mathbf{x}) - f(\mathbf{x}_{-i}, x_i=0)$$
While computationally cheap ($O(D)$ model calls), heuristic ablation **violates the Efficiency (Additivity) Axiom**: the sum of heuristic contributions does not equal the difference between the model's actual prediction and its expected value:
$$\sum_{i=1}^D \text{contrib}_{heuristic}(i) \ne f(\mathbf{x}) - \mathbb{E}[f(\mathbf{x})]$$

### Exact TreeSHAP (Lundberg et al., Nature MI 2020)
TreeSHAP computes exact Shapley values from cooperative game theory in polynomial time ($O(T L D^2)$ where $T$ is trees, $L$ is max leaves, $D$ is depth):
$$\phi_i(f, \mathbf{x}) = \sum_{S \subseteq F \setminus \{i\}} \frac{|S|! (|F| - |S| - 1)!}{|F|!} \left[ f_x(S \cup \{i\}) - f_x(S) \right]$$

### Mathematical Properties Enforced:
1. **Efficiency / Additivity (Strictly Verified in CI):**
   $$f(\mathbf{x}) = \phi_0 + \sum_{i=1}^D \phi_i(\mathbf{x}) \pm \epsilon, \quad |\epsilon| < 10^{-3}$$
   where $\phi_0 = \mathbb{E}[f(\mathbf{x})]$ is the base value of the tree ensemble.
2. **Symmetry:** If two features contribute identically across all tree splits, their Shapley values are equal.
3. **Null Player:** If a feature does not affect any tree split decision for a sample, its attribution is zero ($\phi_i = 0$).

---

## 2. Integration & Latency Profile

Pahredaar-IoT wraps its tree models using `TreeShapExplainer`:
- **Model Support:** `RandomForestClassifier` (Gate and Multiclass heads).
- **Latency Measurement:**
  - Exact TreeSHAP inference latency: $\approx 15-25$ ms per single flow explanation on CPU.
  - Heuristic Ablation fallback latency: $\approx 6-10$ ms.
- **Fail-Safe Architecture:** If `shap` is missing or encounters unhandled edge cases, `TreeShapExplainer` automatically and gracefully falls back to `ablation_fallback` with explicit telemetry logging.

---

## 3. Output Schema Contract

```json
{
  "predicted_class": "ddos",
  "target_class_idx": 1,
  "base_value": 0.0021,
  "satisfies_additivity": true,
  "reconstructed_prediction": 0.9998,
  "actual_model_output": 0.9998,
  "method": "exact_treeshap",
  "latency_ms": 18.42,
  "top_features": [
    {
      "feature": "pkt_rate",
      "raw_value": 8998.2,
      "scaled_value": 5.42,
      "contribution": 0.4821
    },
    {
      "feature": "total_bytes",
      "raw_value": 1200.0,
      "scaled_value": 2.11,
      "contribution": 0.2315
    }
  ]
}
```
