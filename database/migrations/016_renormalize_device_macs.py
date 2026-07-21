"""
016_renormalize_device_macs.py
===============================
Re-run the 015 device-MAC cleanup now that the *writer* is fixed.

015 merged mixed-case duplicate rows and dropped broadcast/multicast rows, but
it could only clean what was already stored — the discovery writer kept
creating fresh upper-case rows immediately afterwards
(``orchestration/discovery_manager.py`` normalised MACs to upper-case for its
local-adapter comparisons and then wrote that same value into the primary key,
while the packet writer wrote lower-case). The live database showed the result:
``EE:C6:46:18:FF:9F`` and ``ee:c6:46:18:ff:9f`` as two rows for one phone,
created hours apart, splitting its traffic totals and its policy/quota
accounting.

That writer now normalises through ``device_queries.normalize_mac`` and rejects
frame addresses, so this pass is the last one needed. It reuses 015's merge
logic verbatim rather than restating it: the operation is identical and
idempotent — only the reason for running it again is new.
"""

import importlib.util
import logging
import os

logger = logging.getLogger(__name__)

_SOURCE = "015_normalize_device_macs.py"


def run():
    """Load 015 by path (its name starts with a digit, so it is not importable
    as a normal module) and re-run it."""
    path = os.path.join(os.path.dirname(os.path.abspath(__file__)), _SOURCE)
    if not os.path.exists(path):
        logger.warning("016: %s not found — nothing to re-run", _SOURCE)
        return

    spec = importlib.util.spec_from_file_location("_migration_015", path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)

    logger.info("016: re-running device MAC normalisation (writer now fixed)")
    mod.run()
