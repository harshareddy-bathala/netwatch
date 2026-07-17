"""
evaluation - NetWatch Evaluation Harness (Phase 4, AI-first)
=============================================================

Capstone-defensible measurement of the intelligence layer:

* :mod:`evaluation.threat_dataset` — a labeled traffic dataset (attacks +
  benign near-misses) covering all five detectors.
* :mod:`evaluation.detector_eval` — precision / recall / F1 and a
  confusion matrix for the threat detector pack.
* :mod:`evaluation.faithfulness` — citation-faithfulness measurement for
  the tool-grounded LLM investigator, plus a tool-grounding ablation.

Everything here is deterministic and model-free by default (the
faithfulness harness accepts any runtime, including the scripted one), so
the whole evaluation runs offline and in CI.
"""
