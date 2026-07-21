# NetWatch — CII demo runbook

Event: **Wednesday 2026-07-22**. Setup: **Windows Mobile Hotspot + phones.**

---

## 30 minutes before

1. **Turn on Windows Mobile Hotspot** (Settings → Network & Internet → Mobile
   hotspot). Leave it on — do not toggle it during the demo.
2. **Connect at least one phone** and leave it connected. Windows tears the ICS
   virtual adapter down when no client is attached, which is what caused the
   mode flapping in the field logs.
3. **Start Ollama and warm the model** — the first generation pays the
   load-from-disk cost, and on this laptop that is ~20s versus ~6s warm:

   ```
   ollama serve
   ollama run llama3.2:3b "ready"      # then Ctrl-D
   ```

   `LLM_KEEP_ALIVE` is already `30m`, so it stays resident once warm.

4. **Run pre-flight** in an **Administrator** terminal:

   ```
   venv\Scripts\python.exe scripts\demo_preflight.py --fix
   ```

   `--fix` only ever *releases* blocks — it can never cut a device off. Do not
   go on stage with any FAIL.

## Starting

```
venv\Scripts\python.exe main.py --mode hotspot
```

`--mode hotspot` pins the capture mode. Without it, an idle moment can make
Windows drop the ICS adapter and NetWatch will legitimately re-detect as
`public_network`, restarting capture mid-demo. Confirm this line in the log:

```
Capture mode PINNED to 'hotspot' — auto-detection disabled
```

Dashboard: <http://127.0.0.1:5000>

---

## Demo sequence

**1. Live monitoring.** Dashboard — bandwidth chart, device count, protocols.
Point out the count matches the Devices page exactly; they use one definition
of "active" (traffic on the wire, not presence in an OS cache).

**2. Per-device visibility.** Activity page — each client's apps by friendly
name (Instagram, YouTube), including over QUIC and Private DNS, from passively
decrypted TLS/QUIC SNI. This is the part most tools cannot do.

**3. AI briefing.** Dashboard → **Brief me**. Plain-English account of the last
10 minutes. Note the label underneath: it says whether the local model wrote it
or it was computed from the facts. Both are grounded in the same gathered data.

**4. Blocking, scoped.** Controls → block `instagram.com` **on one phone**.
Within ~15s Instagram fails on that phone while the *other* phone and this
laptop keep working. Show the enforcement badge reading `windivert` — that is
kernel packet-drop, which DoH and QUIC cannot bypass. Then unblock; it recovers
without restarting anything.

**5. Sense → reason → act.** Generate threats:

```
venv\Scripts\python.exe scripts\redteam_demo.py
```

Security page → open an incident → the **AI assessment** card appears.

- On the DNS-tunnelling incident it should say **dismiss as benign** — the
  domain is a known CDN, and the shape of CDN hostnames is identical to
  exfiltration. A tool that cries wolf is worse than one that talks you down.
- On the port-scan + lateral-movement incident it should say **quarantine**.
- Click **Quarantine device (1 hour)**. That writes a real, scoped, expiring
  policy — visible on Controls as "Paused until HH:MM", releasable by the same
  button as any other block.

The line to say out loud: *nothing is ever applied automatically, and the model
cannot lower a containment decision — only raise it.*

---

## If something goes wrong

| Symptom | Cause | Do this |
|---|---|---|
| Device count wrong / stuck | Hotspot adapter dropped | Check a phone is still connected; the pin holds the mode but capture needs the adapter |
| Blocking has no effect | `pydivert` missing or not elevated | Enforcement badge will read `dns` or `unavailable` — restart elevated |
| AI card slow (~20s) | Model was not warmed | It still works; the second call is ~6s |
| AI card says "evidence rules" | Ollama not reachable | Feature still works — this is the deterministic path, by design |
| A device is stuck blocked | Leftover pause | `scripts\demo_preflight.py --fix` |

**Fallback if the venue network misbehaves:** the AI briefing and the incident
assessment both work with no clients and no model. Run `redteam_demo.py` and
demo the Security page, which needs neither.

---

## Known limitations (say these if asked — they are honest, not excuses)

- **Blocking is hotspot-only.** It works because this host is the clients'
  gateway. In any other mode rules are saved but not enforced, and the UI says
  so rather than pretending.
- **A network-scoped domain rule affects this host too.** That is what
  "network-wide" means; per-device scope is the default precisely because it
  does not.
- **CDN IP blocking can over-reach.** Big providers share address space, so
  blocking one Meta domain can affect other Meta services.
- **The local model is a 3B.** It is used to *explain*, and its recommendation
  is bounded by a deterministic assessment of the same evidence — measured, it
  was wrong in both directions when trusted alone.
- **A device seen only over IPv6 link-local** can appear as an `fe80::…` row
  with no friendly name until it sends IPv4 traffic. Cosmetic; it resolves once
  the client is actually active on the hotspot.

---

## After the demo

```
venv\Scripts\python.exe scripts\demo_preflight.py --fix     # release any blocks
```

Leaving a phone quarantined is the single easiest way to confuse yourself
later — a pause set during a rehearsal was still dropping a device's traffic
hours afterwards, which is why pauses now expire by default.
