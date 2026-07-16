"""
eval_faithfulness.py - Citation-Faithfulness Runner (Phase 4)
==============================================================

Measures how faithfully the tool-grounded investigator's answers are
supported by the data it retrieved, and runs a tool-grounding ablation
(grounded investigator vs the same model answering with no tools).

Requires a local model (Ollama).  With none reachable it reports that and
exits 0 — the metric code itself is exercised by tests with the scripted
runtime; this script produces the real numbers against llama3.

Usage::

    python scripts/eval_faithfulness.py
    python scripts/eval_faithfulness.py --json --out docs/evaluation/faithfulness.json
"""

import argparse
import json
import os
import sys

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from evaluation.faithfulness import evaluate_batch, ablation  # noqa: E402

# A small, fixed question set touching each tool. Questions are phrased to
# demand *checkable* facts (counts, rates, addresses): an answer with no
# numbers in it scores claim_support 1.0 by default and measures nothing.
QUESTIONS = [
    "Are there any open incidents right now?",
    "How much bandwidth is the network using and how many devices are active?",
    "How many active devices are there? Give the exact number.",
    "What are the top protocols on the network and how many bytes has each moved?",
    "What is the current download and upload rate in Mbps?",
    "Which devices are talking to external hosts?",
    "Is anything suspicious happening on the network?",
    "Summarise the current state of the network in one sentence, with numbers.",
]

_UNGROUNDED_PROMPT = (
    "You are a network assistant. Answer the question in one or two "
    "sentences from your own knowledge. Do not ask for data.\n\nQuestion: {q}"
)


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--json", action="store_true")
    parser.add_argument("--out", default=None, help="write JSON report here")
    parser.add_argument("--model", default=None, help="Ollama model name")
    parser.add_argument("--no-seed", action="store_true",
                        help="evaluate against the live DB as-is instead of "
                             "the deterministic seeded network")
    args = parser.parse_args(argv)

    from config import LLM_MODEL, LLM_MAX_STEPS
    from intelligence.investigator import build_investigator
    from intelligence.llm_runtime import get_runtime

    seed_info = None
    if not args.no_seed:
        # Against an idle DB the model can only truthfully say "nothing is
        # happening" — no checkable facts, so claim_support is a free 1.0.
        # Seed a deterministic network so the metric has something to bite on.
        from evaluation.network_seed import seed_network
        seed_info = seed_network()
        print(f"seeded network: {seed_info['devices']} devices, "
              f"{seed_info['traffic_rows']} traffic rows on "
              f"{seed_info['subnet']}")

    model = args.model or LLM_MODEL
    investigator = build_investigator(model=model, max_steps=LLM_MAX_STEPS)
    if investigator is None:
        print("No local LLM runtime reachable — install Ollama and "
              f"`ollama pull {model}` to run the faithfulness evaluation.")
        return 0

    runtime = get_runtime(model=model)

    def ungrounded(question: str) -> str:
        return runtime.generate([
            {"role": "user", "content": _UNGROUNDED_PROMPT.format(q=question)},
        ])

    # A quick probe: the tags endpoint can be up while the model isn't
    # pulled yet (chat 404s).  Fail clearly rather than scoring a dead run.
    from intelligence.llm_runtime import LLMUnavailable
    try:
        runtime.generate([{"role": "user", "content": "ok"}])
    except LLMUnavailable as exc:
        print(f"Ollama is running but model '{model}' isn't ready yet "
              f"({exc}). Finish `ollama pull {model}` and re-run.")
        return 0

    batch = evaluate_batch(investigator, QUESTIONS)
    abl = ablation(investigator, ungrounded, QUESTIONS)

    payload = {
        "model": model,
        "network": seed_info or {"seeded": False,
                                 "note": "evaluated against live DB as-is"},
        "faithfulness": {
            "n": batch.n,
            "mean_citation_validity": batch.mean_citation_validity,
            "grounded_rate": batch.grounded_rate,
            "mean_claim_support": batch.mean_claim_support,
            "answers_with_facts": batch.answers_with_facts,
            "total_facts": batch.total_facts,
            "unsupported_facts": batch.unsupported_facts,
            "hallucination_rate": batch.hallucination_rate,
            "failed": batch.failed,
            "per_question": batch.per_question,
        },
        "ablation": abl,
    }

    if args.out:
        with open(args.out, "w", encoding="utf-8") as fh:
            json.dump(payload, fh, indent=2)
        print(f"faithfulness report written to {args.out}")

    if args.json:
        print(json.dumps(payload, indent=2))
    else:
        def _rate(v):
            return "n/a (no facts)" if v is None else f"{v:.3f}"

        print(f"\nCitation-Faithfulness ({model})")
        print(f"  scored            : {batch.n}/{len(QUESTIONS)} investigations")
        if batch.failed:
            print(f"  !! FAILED         : {len(batch.failed)} never completed "
                  f"(excluded from scores)")
            for f in batch.failed:
                print(f"       - {f['question'][:50]}: {f['reason'][:60]}")
        print(f"  citation validity : {batch.mean_citation_validity:.3f}")
        print(f"  grounded rate     : {batch.grounded_rate:.3f}")
        print(f"  claim support     : {batch.mean_claim_support:.3f} "
              f"({batch.answers_with_facts}/{batch.n} answers had checkable facts)")
        print(f"  hallucinated facts: {batch.unsupported_facts}/{batch.total_facts} "
              f"-> rate {_rate(batch.hallucination_rate)}")
        print(f"\nAblation (tool-grounded vs no tools):")
        print(f"  grounded claim support   : {abl['grounded_mean_claim_support']:.3f}")
        print(f"  ungrounded claim support : {abl['ungrounded_mean_claim_support']:.3f}")
        print(f"  delta (grounding gain)   : {abl['delta']:+.3f}")
        gf, uf = abl["grounded_facts"], abl["ungrounded_facts"]
        print(f"  grounded hallucination   : {gf['unsupported_facts']}/"
              f"{gf['total_facts']} -> {_rate(gf['hallucination_rate'])}")
        print(f"  ungrounded hallucination : {uf['unsupported_facts']}/"
              f"{uf['total_facts']} -> {_rate(uf['hallucination_rate'])}\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
