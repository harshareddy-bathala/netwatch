"""
orchestration - Application Lifecycle Management
==================================================

Decomposes the main.py god object into focused modules:

* **state**             — Shared singletons and synchronization primitives.
* **shutdown**          — Graceful shutdown sequence with watchdog.
* **mode_handler**      — Mode change callbacks, capture engine lifecycle.
* **discovery_manager** — Device discovery loop, ARP/ping scanning.
* **background_tasks**  — Cleanup scheduler, anomaly detector, health monitor,
                          thread watchdog.
"""
