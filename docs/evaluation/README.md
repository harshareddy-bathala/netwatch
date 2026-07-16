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

**The seeded network** (`evaluation/network_seed.py`). The evaluation runs
against a deterministic seeded network (7 devices, ~600 traffic rows, a
realistic HTTPS/DNS/HTTP mix) rather than the live database. This is a
methodological necessity, not decoration: against an **idle** database the
investigator can only truthfully answer *"the network is not active, 0
devices, 0 bandwidth"* — an answer with no checkable facts in it, which
scores `claim_support = 1.0` for free. The first live run did exactly
that, scoring a flattering **1.000 on 2 facts across 5 questions**. A
populated network forces the model to commit to counts, rates and
addresses that the metric can actually verify — and that an ungrounded
model must invent. Devices are placed in the host's detected subnet
because the active-device query filters to the current subnet.

**Metric** (`evaluation/faithfulness.py`): consumes the investigator's
structured result (`answer`, `tool_calls`, `citations`) and computes, per
investigation:

- **citation_validity** — fraction of cited tools the investigation
  actually called (a citation to an uncalled tool is unfaithful);
- **grounded** — whether the answer rests on ≥1 tool call;
- **claim_support** — fraction of the answer's *checkable facts* (numbers,
  IPs, MACs) that appear in the concatenated tool results. An unsupported
  number in the answer is a hallucination.

**Reading claim_support honestly.** An answer with nothing checkable in it
("the network looks fine") scores `claim_support = 1.0` by definition —
there is no claim to contradict. A macro mean over mostly fact-free
answers therefore looks perfect while measuring almost nothing. The report
exposes this rather than hiding it: `answers_with_facts` / `total_facts`
give the coverage, and **`hallucination_rate`** is micro-averaged *over
facts* (`unsupported_facts / total_facts`, `null` when there were no
facts). The micro rate is the discriminating number and the one to quote;
the macro mean is kept for continuity.

**Ablation** — the same questions answered by (a) the tool-grounded
investigator vs (b) the same model with no tools, scored against the same
retrieved facts. Grounding is expected to raise claim support.

**Running it** (needs a local model):

```
ollama pull llama3
python scripts/eval_faithfulness.py --out docs/evaluation/faithfulness.json
python scripts/eval_faithfulness.py --no-seed    # against the live DB as-is
```

The metric itself is fully covered by `tests/test_evaluation.py` using the
deterministic scripted runtime, so the pipeline is verified without a
model; the script produces the real numbers once `llama3` is pulled.
NetWatch talks only to a local Ollama server — the evaluation is entirely
offline.

### What the live model exposed

Running the harness against real llama3 (rather than the scripted runtime)
surfaced four defects that model-free tests structurally could not:

1. **Non-string answers.** llama3 answers a yes/no question with a JSON
   *boolean* (`{"answer": true}`). Everything downstream assumed a string;
   this crashed the metric and would have 500'd `/api/investigate`. Fixed
   by coercing the answer at the investigator boundary.
2. **Ungrounded answers with fabricated citations.** The first live run
   scored **grounded rate 0.000, citation validity 0.200** — the model
   answered at step 0 with no data and cited `list_incidents` (and even
   the string `"status=open"`) without ever calling anything. The cause
   was our own prompt ("prefer the fewest tool calls"). Rewording alone
   did *not* fix it; grounding is now **enforced in the loop** — an
   attempt to answer with no tool calls is rejected once and the model is
   told to retrieve first. Grounded rate went 0.000 → 1.000.
3. **Timeout too short.** 60s was insufficient for an 8B model on CPU once
   tool results lengthen the transcript, killing investigations mid-run.
   Now `LLM_TIMEOUT_SECONDS` (default 180).
4. **A metric that flattered itself.** See "Reading claim_support
   honestly" above — fixed with fact-coverage fields and a micro-averaged
   hallucination rate.

Finding (2) is the substantive one: it shows that *prompting* a small
local model to be faithful is insufficient, and that the tool-calling
loop must enforce retrieval structurally. That is a defensible result in
its own right.

### Model choice is an evaluation finding, not a footnote

NetWatch is local-first, so the model must run on an ordinary laptop.
Measured on an 8 GB host (7.35 GB usable):

| model | size | resident | same question | outcome |
|---|---|---|---|---|
| llama3 (8B) | 5.3 GB | 86% (0.7–1.5 GB paged out) | **67.4s** | correct |
| **llama3.2:3b** | 2.6 GB | ~100% | **26.8s** | correct |

llama3 does not fit alongside the application: `llama-server` showed
Private 5.08 GB against a 3.55 GB working set — 1.5 GB of weights evicted
to disk — with sustained 12k–115k hard page-faults/sec at ~130 MB free.
Generation is ~2.5x slower purely from paging, which is what caused the
60s timeouts, *not* CPU speed. `llama3.2:3b` is the default for this
reason; `NETWATCH_LLM_MODEL` overrides it on larger hosts.

### Optimising for a 3B model

The 3B model's measured failure modes drove concrete changes, each of
which is a general lesson for grounding small local models:

- **It cannot do arithmetic reliably.** Asked for protocol byte counts it
  converted raw bytes into `548.7 MB` / `320.8 MB` / `191.9 MB` — numbers
  present in no tool result, i.e. hallucinations by construction. The
  tools now return pre-converted `human` and `summary` fields so the model
  **quotes instead of computes**, and the prompt forbids unit conversion.
- **Protocol corrections starved retrieval.** The grounding nudge and
  unparseable-retry each consumed a step of the tool budget, so 2 of 8
  questions gave up before answering. The budget now counts *tool calls*
  only; corrections are free, bounded by a separate iteration ceiling.
- **Giving up is worse than answering partially.** Exhausting the budget
  used to return "I couldn't reach a grounded answer". It now forces a
  final answer from whatever was already retrieved.

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
