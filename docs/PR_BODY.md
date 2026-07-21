# CII demo readiness: correctness fixes + AI-first surface

Fixes the three defects reported from the 2026-07-20 field session, plus one
found during verification. All four were reproduced from `logs.txt` and the
live DB before being fixed.

They share a theme: several subsystems treated **"the OS still remembers
this"** as **"this is true right now"**.

## 1. Network interruptions — mode flapping

Windows tears down the ICS virtual adapter whenever the hotspot has no client,
so the mode oscillated `hotspot → public_network → hotspot` roughly every 30s.
Each pass restarted capture, reset the digital twin and re-scoped every device
row. On stage that reads as the app crashing.

- `--mode` / `NETWATCH_FORCE_MODE` pins the mode. A pinned mode whose interface
  is absent **holds** rather than falling back — falling back *is* the flap.
- Leaving hotspot now needs 12 detections + 60s cooldown (was 3 + 15s).
  Entering stays instant: leaving is expensive, entering is cheap.
- `notify_interface_lost` no longer short-circuits that threshold. It sets a
  restart flag so capture rebuilds when ICS returns the same adapter — which
  previously left capture dead.
- A failed `Get-NetAdapter` probe now reads as *unknown*, not *inactive*.
- `--mode port_mirror` also makes SPAN capture deterministic.

## 2. Device count stuck at 1

`HOTSPOT_ACTIVE_PROBING` is off by default, so `arp_scan`/`ping_sweep` never
run in hotspot — **every corroboration test AND-ing against them was dead code
in the one mode that matters.** The surviving gate was
`bool(ip_val) or source == "hostednetwork"`, and since Win10/11 Mobile Hotspot
has no legacy hosted network, the client list falls back to the ARP table where
every entry has an IP. The gate was unconditionally true, so a departed phone
was re-promoted every cycle, forever.

- `DeviceInfo.last_packet_seen`, stamped **only** by the packet path. Presence
  makes a device visible; only traffic makes it *active*. In hotspot this host
  is the gateway, so a genuinely connected client cannot stay silent.
- A just-joined client keeps a 30s grace bounded by `first_seen` (which
  discovery never refreshes), capped at the caller's active window.
- One MAC normaliser for every writer — `packet_store` wasn't normalising at
  all, a second source of duplicate rows. Migration 016 re-merges the rest.

## 3. Blocking: unreliable *and* collateral, from one cause

Enforcement dropped every blocked domain by **bare server IP**, so a rule
naming one phone cut the site off for every other client *and for the laptop
running NetWatch*. It looked broken because it hit the wrong things.

| kind | filter | meaning |
|---|---|---|
| device block | `SrcAddr==C or DstAddr==C` | everything for that client — the intent |
| **per-device domain** | `(Src==C and Dst==S) or (Src==S and Dst==C)` | only that client's conversation |
| network-wide | `SrcAddr==S or DstAddr==S` | everyone, on purpose |

- `blocking_rules.scope` (`device` default \| `network`); migration 017.
- The SNI learner attributes learned IPs to their domain family, so blocking
  Instagram on one phone and YouTube on another no longer pools both.
- MAC→IP is recency-bounded; an absent device enforces nothing rather than
  guessing an address DHCP may have reassigned.
- The DNS sinkhole is **hotspot-only** — it was starting on Wi-Fi in
  `public_network`, NXDOMAINing the admin's own lookups.
- Pauses expire (default 60m). A rehearsal pause was still blackholing a phone
  hours later.

## 4. Found during verification: `devices.last_seen` written in local time

The Devices page showed a device **"-95 minutes ago"**. `packet_store` wrote
`last_seen` from the packet's *local* timestamp while every reader compares
against UTC — putting traffic-seen devices 5.5h in the future so they never
aged out, **silently defeating both the active-window count and the new
blocking recency bound**. Device timestamps are now UTC; traffic tables keep
the packet's own clock.

## AI-first surface

**`intelligence/responder.py`** — assesses one incident and proposes an action
for a human to approve. Nothing is auto-applied; approval routes through the
ordinary scoped, expiring, reversible policy path.

Measured on `llama3.2:3b` against this project's own evidence, the model was
wrong in **both** directions: it called a benign Meta-CDN DNS burst
*"quarantine"*, and — once given domain context it cannot be expected to
recall — called a corroborated port scan *"a legitimate port scan, likely from
an authorized device"*. So the deterministic assessment sets a **containment
floor the model may raise but never lower**, and the override is displayed
rather than hidden. The model keeps the job it is good at (explaining) and
loses the authority it demonstrably could not hold.

**`intelligence/briefing.py`** — "what just happened?" over the last N minutes.
Facts are gathered deterministically; the model only *narrates* them, so it
cannot invent a device or a domain.

Both features work with **no model at all** — the deterministic path is the
floor, exercised on every run.

## Verification

- **1279 tests passing** (baseline 1145), 0 failures.
- Detector eval unchanged: **macro-F1 1.000, benign FP-rate 0.000**.
- All 15 page APIs exercised against a running instance; bps↔Mbps consistent.
- Both AI endpoints verified end-to-end against the real local model
  (13.6s cold, 6.4s warm).
- Migrations 016/017 verified idempotent on an isolated copy of the live DB.

## Not verified — needs hardware

The 8-step live hotspot checklist (count reads 0 with nothing connected;
per-device block leaves the second phone working; 20 minutes with zero
`Mode change` lines) **requires a real hotspot and two phones**. Steps are in
`docs/DEMO_RUNBOOK.md`; run `scripts/demo_preflight.py --fix` first — it only
ever *releases* blocks, never applies them.

Known cosmetic issue, documented: a device seen only over IPv6 link-local can
appear as an `fe80::…` row with no friendly name until it sends IPv4 traffic.
