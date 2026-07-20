# NetWatch — AI/ML Concepts You Should Be Confident About

This is your study sheet for AI/ML questions. It covers **what every intelligent
part of NetWatch actually is**, in ML terms (supervised vs unsupervised,
classification vs regression, etc.), **why that choice was made**, and the concepts
you need to answer follow-ups without bluffing.

**The honest framing to hold in your head (and say out loud):**
NetWatch is a system where **the right technique is used for each job** — some
genuine machine learning, some classical statistics, some deterministic rules, and
one large language model as the conversational surface. That is a *strength*, not a
weakness. Reaching for a neural network to count devices would be over-engineering.
A senior engineer picks the simplest method that is correct. If a judge asks "is
this really AI?", the confident answer is: *"It's the appropriate model for each
task — an unsupervised anomaly detector, online statistical baselines, a
time-series forecaster, and a locally-run LLM. We didn't bolt on deep learning
where statistics is more honest and more explainable."*

---

## Part 1 — The ML vocabulary (know these cold)

**Supervised learning** — you train on **labelled** examples (input → known
correct answer) so the model learns to predict the label on new data. Needs a
labelled dataset. Two sub-types:
- **Classification** — predict a **category** (spam / not-spam; phone / laptop / TV).
- **Regression** — predict a **number** (tomorrow's bandwidth in Mbps).

**Unsupervised learning** — **no labels.** The model finds structure on its own.
Sub-types you'll cite:
- **Anomaly / outlier detection** — learn what "normal" looks like, flag what
  doesn't fit. *(This is NetWatch's main ML model.)*
- **Clustering** — group similar things (we don't use this, but know the word).

**Why unsupervised matters here:** nobody hands you a labelled dataset of "normal
vs malicious" traffic for *your* specific network. Labels don't exist, and every
network is different. So supervised learning is often the *wrong* tool for security
on a live network — you learn the normal of *this* network and flag deviation.

**Features** — the measurable inputs a model sees (e.g. bytes per minute, number of
connections, protocol count). "Feature engineering" = choosing good ones. Models are
only as good as their features.

**Model vs heuristic vs statistic:**
- A **model** is fitted/trained from data (Isolation Forest, Holt).
- A **heuristic / rule** is a hand-written condition ("30+ ports in 60s = scan").
- A **statistic** is a computed summary (mean, standard deviation, z-score).
All three are legitimate. Rules are often *better* than ML for known attack
signatures — precise, explainable, no training data needed.

**Evaluation words** (in case they ask "how do you know it works"):
- **Precision** = of the things you flagged, how many were right. High precision =
  few false alarms.
- **Recall** = of the real problems, how many you caught.
- **F1 score** = the balance of the two (harmonic mean). *NetWatch's detector evals
  target macro-F1 = 1.0 with 0 false positives on the benign set.*
- **False positive** = a false alarm. In a home/campus tool, false positives are
  the #1 way to lose the user's trust — which is why thresholds are deliberately
  conservative.

---

## Part 2 — What each NetWatch component is, and why

### 1. Anomaly Detection → **Isolation Forest** (unsupervised ML)

- **Type:** Unsupervised machine learning — outlier detection. An ensemble of
  random decision trees.
- **What it is:** `sklearn.ensemble.IsolationForest`, **200 trees**,
  `contamination = 0.01` (we expect ≈1% of windows to be anomalous). Inputs are
  standardised first (`StandardScaler` → zero mean, unit variance) so no single
  feature dominates by its units.
- **The 8 features** (per time window): total bandwidth, active connections, unique
  protocols, TCP-retransmit ratio, ICMP-unreachable rate, DNS query count, HTTP
  request count, HTTPS request count.
- **How it works (one sentence):** it isolates points by random splits; **anomalies
  get isolated in fewer splits** because they sit apart from the dense normal
  region — the shorter the path to isolate a point, the more anomalous it is.
- **Why this model:** (a) **unsupervised** — no labelled attack data required;
  (b) it's **fast and scales** to lots of data; (c) it's **robust in
  high-dimensional feature space**; (d) it doesn't assume the data is a neat bell
  curve. It's the textbook choice for "flag the weird traffic without being told
  what weird looks like."
- **Likely Q:** *"Why not a neural network / deep learning?"* → "We have modest,
  tabular, low-dimensional data and need explainability and CPU-only, offline
  operation. Deep learning would need far more data, more compute, and give a less
  interpretable answer. Isolation Forest is the right-sized tool."

### 2. Per-device Behaviour Baselines → **online statistics + z-score** (statistical anomaly detection)

- **Type:** Not a trained ML model — **online (streaming) statistics**, a form of
  unsupervised anomaly detection by threshold.
- **What it is:** for every **(device × hour-of-week × metric)** it keeps a running
  **mean and variance** using **Welford's algorithm** — an online method that
  updates count/mean/variance one sample at a time without storing history (O(1)
  memory). A live value is scored by its **z-score** = how many standard deviations
  it is from that baseline; beyond `z = 4.0` (with ≥12 baseline samples) it becomes
  evidence.
- **Why this, not ML:** the question is "is this device unusual **for itself, right
  now (this hour of the week)**?" That's inherently **per-device and
  per-time-slot** — a global model would drown a quiet IoT sensor and a busy laptop
  in the same average. Welford is exact, tiny, streaming (fits a live capture with
  no retraining), and **fully explainable**: "3pm-Tuesday, this device is 6σ above
  its own normal." An anomalous window is deliberately **not** folded back into the
  baseline, so an attack doesn't teach the model that the attack is normal.
- **Concept to name-drop:** *hour-of-week seasonality* (0–167). Networks have daily
  and weekly rhythms; baselining per hour-of-week captures them.

### 3. Bandwidth Forecast → **Holt's double-exponential smoothing** (time-series regression)

- **Type:** **Regression**, specifically **time-series forecasting**. Predicts a
  number (future Mbps), so it's regression-family.
- **What it is:** **Holt's linear-trend (double-exponential) smoothing** — it tracks
  two things: a smoothed **level** (where bandwidth is) and a **trend** (which way
  it's moving), with smoothing weights `alpha = 0.5` (level) and `beta = 0.1`
  (trend). Forecast = level + trend × steps ahead. It also emits a **confidence band
  that widens with the horizon** (further out = less certain).
- **Device-count trend** uses a simple **least-squares linear fit** — also
  regression.
- **Why this, not an LSTM/Prophet:** it's **compute-on-demand, no training, no
  dependencies, fully offline**, and appropriate for short-horizon (~30 min)
  smoothing on noisy per-minute data. A heavyweight forecaster would be
  over-engineering for a 30-minute look-ahead and couldn't run live on a laptop.
- **Concept:** *exponential smoothing* = recent observations weighted more than old
  ones. "Double" = it smooths both level **and** trend (single would miss the slope).

### 4. Threat Detection → **rule/heuristic detectors + one entropy statistic** (deterministic, explainable)

- **Type:** Mostly **deterministic heuristics** (expert rules), not learned models —
  by design.
- **The five detectors:** port scan, beaconing (regular "phone-home" intervals),
  DNS tunnelling, rogue device, lateral movement. Examples of the logic:
  - **Port scan** → one source hitting more than a threshold of distinct ports/hosts
    in a window.
  - **Beaconing** → connections at suspiciously **regular** intervals (low jitter);
    malware calling home ticks like a clock, humans don't.
  - **DNS tunnelling** → uses **Shannon entropy** of the domain name: data smuggled
    inside DNS looks like high-entropy random strings, not real words.
- **Why rules, not ML:** these are **known attack signatures** with crisp
  definitions. A rule is **more precise, needs no training data, and is fully
  explainable** ("we flagged this because it contacted 47 ports in 12 seconds").
  Using ML here would add false positives and remove the clear reason. **Every alert
  carries its evidence and a confidence score.** This is the mature choice, and
  saying so reads as expertise.
- **Concept:** *Shannon entropy* = a measure of randomness/information. Say:
  "`aGVsbG8gd29ybGQ.example.com` has high entropy — that's data hidden in a domain
  name, not a real hostname."

### 5. Incident Fusion & Risk Scoring → **correlation + weighted scoring** (deterministic)

- **Type:** Rule-based **correlation** + a **weighted risk score**, not a model.
- **What it does:** groups alerts sharing a device/time window into one **incident**,
  and scores it by **severity × confidence × recency × device sensitivity**.
- **Why:** the goal is to turn "a wall of 40 alerts" into "3 things that matter,
  ranked." That's an **information-design and prioritisation** problem, best solved
  transparently so the user can see *why* something is ranked high.

### 6. Device Identification → **fingerprint lookup / classification** (deterministic classifier)

- **Type:** **Classification**, but done by **deterministic lookup**, not a trained
  classifier. Output: `{device_type, confidence, label}`.
- **Signals used (all passive):** the **OUI** (first half of the MAC = the hardware
  vendor), the **DHCP Option-55 fingerprint** (the specific list of options a device
  asks for is OS-distinctive), and DHCP/mDNS **hostnames**.
- **Why lookup, not ML:** these signals map to device types **deterministically and
  reliably** — a MAC vendor prefix *is* the manufacturer; there's no uncertainty to
  learn. A trained classifier would be strictly worse: more complexity, less
  reliability, and it would need labelled data we don't need. It **reports a
  confidence** so a weak guess reads as a guess.
- **Concept:** *passive fingerprinting* = identifying a device from traffic it emits
  anyway, without probing or scanning it.

### 7. Traffic / App Classification → **handshake-name mapping** (deterministic)

- **Type:** Deterministic **mapping**, not ML. `i.instagram.com → Instagram / Meta`.
- **What it is:** read the **SNI** (the plaintext server name in the TLS/QUIC
  handshake) — including **decrypting the QUIC Initial packet per RFC 9001** to
  recover it for HTTP/3 apps — then map the domain (and its whole app family) to a
  human app + operator via a catalogue.
- **Why not ML:** the name is *right there* and the mapping is a known fact. ML would
  only add error. The genuinely clever engineering is **recovering the name from
  encrypted transports without decrypting any content**, not classifying it.

### 8. Ask NetWatch → **local Large Language Model, tool-grounded** (generative AI + RAG-style grounding)

- **Type:** A **pre-trained generative LLM** run **locally** (via Ollama, a small
  ~3-billion-parameter instruction model, e.g. `llama3.2:3b`). We **don't train or
  fine-tune it** — we *ground* it.
- **How it's grounded (this is the important part):** the model **cannot** answer
  from memory. It must call **read-only tools** that query NetWatch's live data,
  and it answers **only** from what those tools return — every answer ships with
  **citations** showing the exact queries used. This is the same idea as
  **RAG (Retrieval-Augmented Generation)** and **tool-use / function-calling**:
  the LLM is a *language interface* over trusted data, not a source of facts.
- **Why local:** privacy is the whole product thesis — the AI assistant must not
  send your network's data to a cloud API. Local also means offline and
  zero-cost-per-query. The trade-off is **latency** (a small model on a CPU takes
  tens of seconds), which we mitigate by keeping the model resident in memory.
- **Why grounding matters:** it's how we **prevent hallucination**. If the tools
  don't have the answer, the model says so rather than inventing one. "Every claim
  is traceable to a query" is a strong, honest line.
- **Concepts to name-drop:** *RAG*, *tool-use / function-calling*, *grounding*,
  *hallucination*, *inference vs training*, *quantised model* (compressed weights so
  a 3B model fits and runs on a laptop).

---

## Part 3 — The questions you'll probably get (and crisp answers)

**"Is this actually AI, or just if-statements?"**
> "It's a mix chosen per task: an unsupervised ML model (Isolation Forest) for
> anomalies, online statistical learning for per-device baselines, a time-series
> forecaster, deterministic detectors for known attacks, and a locally-run LLM for
> the natural-language interface. Using ML everywhere would be over-engineering —
> for known attack signatures, a precise rule beats a black box."

**"Why not deep learning / a neural network?"**
> "Our data is tabular, low-dimensional, and modest in volume, and we need
> explainability plus CPU-only offline operation. Deep learning needs far more data
> and compute and gives a less interpretable result. We picked right-sized models."

**"Supervised or unsupervised?"**
> "The security ML is **unsupervised** — there's no labelled 'normal vs attack'
> dataset for a specific live network, and every network differs. We learn each
> network's own normal and flag deviation. Forecasting is regression; device typing
> is deterministic classification."

**"How do you avoid false positives?"**
> "Conservative thresholds (behaviour needs a 4-sigma deviation and ≥12 baseline
> samples), every alert carries evidence and a confidence score, and related alerts
> are fused into one incident. Our detector evaluation targets zero false positives
> on benign traffic."

**"Does the LLM make things up?"**
> "It can't answer from memory — it's forced to call read-only tools and answer only
> from live data, and every answer shows its citations. That's retrieval-augmented
> generation: the model is a language interface over trusted data, not a fact source."

**"How does it learn / does it need training?"**
> "The Isolation Forest is fitted from the network's own recent traffic. The
> behaviour baselines learn continuously online — Welford's algorithm updates
> mean/variance one sample at a time, no retraining. The LLM is pre-trained and used
> as-is. Nothing needs a labelled dataset or a cloud training run."

**"What ML library?"** → "scikit-learn for the Isolation Forest and scaler; NumPy/
pandas for feature math; Ollama for the local LLM. All standard, all offline."

**"Can it scale to a big campus network?"** → "The models are cheap: Isolation
Forest is fast, the baselines are O(1)-per-sample streaming stats, detection is a
bounded per-device state. The heavy part is packet capture, not the ML."

---

## Part 4 — Ten-second glossary (last-minute cram)

| Term | One line |
|---|---|
| Supervised | trained on labelled data (input → known answer) |
| Unsupervised | finds structure with no labels |
| Classification | predicts a category |
| Regression | predicts a number |
| Anomaly detection | learn normal, flag the odd one out (unsupervised) |
| Isolation Forest | tree ensemble; anomalies isolate in fewer splits |
| Welford's algorithm | compute mean/variance online, one sample at a time |
| z-score | how many standard deviations from the mean |
| Holt smoothing | forecasts level + trend; recent data weighted more |
| Shannon entropy | measure of randomness — high = looks encrypted/random |
| Feature | a measurable input to a model |
| Precision / Recall / F1 | few false alarms / caught the real ones / their balance |
| LLM | large language model — generative, pre-trained |
| RAG | retrieval-augmented generation — LLM answers from fetched data |
| Grounding | forcing the LLM to answer only from real, cited data |
| Hallucination | an LLM confidently inventing something false |
| Inference vs training | *using* a model vs *building* it |
| Quantised model | compressed weights so a model runs on modest hardware |
| OUI | MAC-address vendor prefix — identifies the manufacturer |
| Passive fingerprinting | identify a device from traffic it emits anyway |

---

*If you remember nothing else: **the right tool for each job.** Unsupervised ML for
the unknown, precise rules for the known, statistics for per-device normal, a
grounded local LLM for language. That sentence answers 80% of AI questions you'll get.*
