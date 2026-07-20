# NetWatch — Pitch Speaker Notes

*Target length: 2–5 minutes. Written to be spoken, not read. The point is **why**,
not how. Pauses marked with `—`. Say the italic lines if you have time; skip them
if you're short.*

---

## 0. The one-liner (10 seconds — memorise this)

> **NetWatch shows you everything on your network and what it's actually doing —
> without installing anything on a single device, and without a byte ever leaving
> the building.**

If you only get one sentence out, that's the one.

---

## 1. The problem (40 seconds)

Think about the network you're on right now — a **campus Wi-Fi**, a **hostel
network**, a **home router**. Dozens, maybe hundreds of devices. Phones, laptops,
smart TVs, someone's game console, IoT gadgets nobody remembers connecting.

Here's the uncomfortable truth: **the person responsible for that network cannot
see what's on it.** Not really.

- Every device talks to hundreds of servers a day. There's no record you can reach.
- **Ninety-nine percent of that traffic is encrypted** — so the old tools that
  worked by reading packet contents now just see noise.
- And phones have started **encrypting their DNS lookups** too — so even the last
  easy signal, "which website did it look up," is disappearing.

*So the honest state of most networks today is: devices you didn't add, talking to
servers you can't name, over connections you can't read.*

---

## 2. Why the existing answers aren't good enough (30 seconds)

You'd think this is solved. It isn't — every option makes you give something up:

- **Cloud dashboards** work — by shipping your network's data to someone else's
  servers. You trade privacy for visibility.
- **Agent-based tools** need software installed on every device. You can't install
  an agent on a guest's phone, or a smart bulb, or the campus printer.
- **Enterprise security appliances** are genuinely capable — and priced and staffed
  for banks, not for a hostel warden or a parent.

Nobody serves the **campus network, the small office, the home**. That's the gap.

---

## 3. The insight — the thing that makes this possible (40 seconds)

Here's the idea the whole product stands on:

> **Encryption hides the *contents* of a connection. It does not hide the
> *destination*.**

To *start* an encrypted connection, a device has to announce — in plain text —
which server it wants to reach. That announcement is called the SNI, and it sits
right there in the handshake, unencrypted, by design.

So NetWatch never breaks any encryption and never reads anyone's messages. It
watches the machine that's already sharing the connection — the router, the
hotspot — and reads only that one public label. From it, we can say
**"this is Instagram," "this is YouTube," "this is a banking app"** — the
*what*, without ever touching the *contents*.

*That's the unlock. Everything else is built on top of it.*

---

## 4. What it actually does — feature by feature, and why each exists (90 seconds)

Walk through these as **problems being solved**, not as a feature list.

**Live map & device list.** *"What's even on my network?"* — Every device appears
the moment it connects, named and typed from its own fingerprint. We identified a
phone as a "Nothing Phone" without ever touching it.

**Activity.** *"What is that device doing right now?"* — Open an app on a phone and
watch it show up on screen, live — recovered from encrypted traffic, by name.

**Controls.** *"Can I actually stop it?"* — Pause a device and it loses the internet.
And crucially, we block the way that *works* on modern apps: not by faking a DNS
answer (apps walk straight past that), but by dropping the real traffic in the
kernel, on addresses we learn from the live connection. This is the honest hard
part most tools get wrong.

**Security.** *"Should I be worried?"* — Instead of a wall of raw alerts, related
events are fused into a single case with a risk score: a scan, a rogue device,
strange beaconing traffic — one story, told once.

**Behaviour & Forecast.** *"Is this normal?"* — It learns what normal looks like
**for each device, at each hour of the week**, so an alert means "unusual *for this
device*," not a generic threshold. And it projects where bandwidth is heading.

**Ask NetWatch.** *"Just tell me in plain English."* — Ask a question, get an answer
grounded in live data, **with citations** — every claim shows the exact query
behind it. It runs a language model **locally**, so even the AI assistant never
phones home.

---

## 5. Why it's different — the spine of the pitch (25 seconds)

Four words. Land each one:

- **Agentless** — nothing installed on any device. It works on the guest phone,
  the TV, the printer.
- **Offline** — capture, storage, analytics, *and the AI* all run on one machine.
  No account, no cloud, no telemetry.
- **It reads encrypted traffic** — by destination, never contents.
- **It enforces for real** — in the kernel, not with a DNS trick that apps ignore.

*Visibility **or** privacy used to be the trade. NetWatch is the tool that refuses
to make you choose.*

---

## 6. Who it's for (15 seconds)

- **College campuses & hostels** — see every device on shared Wi-Fi, catch the
  rogue one, keep the network healthy, without an IT team or a per-device agent.
- **Homes & families** — know what the kids' devices and the smart gadgets are
  doing, pause a device at dinner, all of it staying inside the house.
- **Small offices** — enterprise-grade visibility priced and operated for people
  who don't have a security operations centre.

---

## 7. Close (10 seconds)

> **NetWatch turns any ordinary machine into a window into your own network —
> private by design, and honest about what it can and can't see.**
>
> Let me show you the live version.

*(→ go to the demo. Dashboard → Devices → Activity → Controls → Security → Ask.)*

---

### If you get exactly 60 seconds

Say sections **0 → 1 (short) → 3 (the insight) → 5 (the four words) → 7**. That's
the whole argument: here's the problem, here's the one idea that cracks it, here's
what makes us different, let me show you.

### The honesty note that *wins* technical audiences

If someone pushes on blocking or on "can you really see encrypted traffic" — lean
in, don't dodge. *"We never decrypt content. We read the one field that has to be
public. And we're honest about the limits — a brand-new server address is reachable
for a few seconds until we learn it."* Being precise about what it **can't** do is
what separates a real tool from a demo, and technical judges know it.
