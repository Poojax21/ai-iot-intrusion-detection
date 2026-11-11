"""
Explainability package supporting exact TreeSHAP and heuristic ablation explanations.
"""

from .shap_explainer import TreeShapExplainer, ExplanationResult

__all__ = ["TreeShapExplainer", "ExplanationResult"]
