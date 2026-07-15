# NetWatch Evaluation Harness (Phase 4)

Reproducible, offline evaluation of NetWatch's intelligence layer. Two
independent evaluations, both deterministic and runnable in CI:

1. **Threat detector precision/recall** — the detector pack against a
   labeled traffic dataset.
2. **Citation-faithfulness** — whether the LLM investigator's answers are
   grounded in the data it retrieved (requires a local model).

Everything here supports two of the capstone's defensible research
contributions: *per-device / signature detection without payload
inspection, with a published labeled dataset*, and *tool-grounded
local-LLM network investigation with citation-faithfulness measurement*.

---

## 1. Threat detector evaluation

**Dataset** (`evaluation/threat_dataset.py`, exported to
[`threat_dataset.json`](threat_dataset.json)): 18 labeled scenarios built
deterministically from a fixed seed.

| label | scenarios |
|---|---|
| port_scan | 4 (vertical + horizontal) |
| beaconing | 2 |
| dns_tunneling | 2 |
| rogue_device | 2 |
| lateral_movement | 2 |
| **benign** | **6** |

The six **benign near-misses** are the point of the dataset — traffic that
superficially resembles an attack but isn't, so precision is a real
measurement rather than a formality:

- normal web browsing (a few ports to a few hosts) — not a port scan
- a single SMB connection to one file server — below the lateral threshold
- ordinary short DNS lookups to varied domains — not tunneling
- an `ip6.arpa` reverse-DNS burst (long qnames, but legitimate) — not tunneling
- irregular periodic traffic (high jitter) — not a beacon
- a known device doing a bit of everything — nothing should fire

**Method** (`evaluation/detector_eval.py`): each scenario is replayed
through the *real* `ThreatDetector` with a controllable clock; known
devices are pre-seeded so benign traffic from established devices does not
trip the rogue-device detector. For each scenario (label `L`, fired set
`F`) and each threat type `T`: `T∈F ∧ L=T` → TP; `T∈F ∧ L≠T` → FP;
`T∉F ∧ L=T` → FN.

**Results** (regenerate with `python scripts/eval_detectors.py`):

```
detector            precision   recall     f1   tp   fp   fn
------------------------------------------------------------
port_scan               1.000    1.000  1.000    4    0    0
beaconing               1.000    1.000  1.000    2    0    0
dns_tunneling           1.000    1.000  1.000    2    0    0
rogue_device            1.000    1.000  1.000    2    0    0
lateral_movement        1.000    1.000  1.000    2    0    0
------------------------------------------------------------
macro-F1 1.000   accuracy 1.000   benign FP-rate 0.000
```

Full machine-readable report: [`detector_eval.json`](detector_eval.json).

**Finding — detector overlap.** An admin-port (445/SMB) *horizontal* sweep
legitimately trips **both** `port_scan` and `lateral_movement`: sweeping
one service port across many internal hosts is simultaneously a scan and a
fan-out on an admin port. This is correct behaviour, not a false positive.
The dataset keeps the `port_scan` label clean by sweeping a non-admin web
port (80); the overlap is documented rather than hidden, and is a natural
discussion point for multi-label detection.

---

## 2. Citation-faithfulness evaluation

**Metric** (`evaluation/faithfulness.py`): consumes the investigator's
structured result (`answer`, `tool_calls`, `citations`) and computes, per
investigation:

- **citation_validity** — fraction of cited tools the investigation
  actually called (a citation to an uncalled tool is unfaithful);
- **grounded** — whether the answer rests on ≥1 tool call;
- **claim_support** — fraction of the answer's *checkable facts* (numbers,
  IPs, MACs) that appear in the concatenated tool results. An unsupported
  number in the answer is a hallucination.

**Ablation** — the same questions answered by (a) the tool-grounded
investigator vs (b) the same model with no tools, scored against the same
retrieved facts. Grounding is expected to raise claim support.

**Running it** (needs a local model):

```
ollama pull llama3
python scripts/eval_faithfulness.py --out docs/evaluation/faithfulness.json
```

The metric itself is fully covered by `tests/test_evaluation.py` using the
deterministic scripted runtime, so the pipeline is verified without a
model; the script produces the real numbers once `llama3` is pulled.
NetWatch talks only to a local Ollama server — the evaluation is entirely
offline.

---

## Reproducing

```
# detector precision/recall (no model needed)
python scripts/eval_detectors.py

# regenerate published artifacts
python scripts/eval_detectors.py \
    --report-out docs/evaluation/detector_eval.json \
    --dataset-out docs/evaluation/threat_dataset.json

# citation-faithfulness (needs `ollama pull llama3`)
python scripts/eval_faithfulness.py

# the whole harness under test
venv/Scripts/python.exe -m pytest tests/test_evaluation.py
```
