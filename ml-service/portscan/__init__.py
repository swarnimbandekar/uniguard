"""Port-scan detection component for the SIH 26145 real-time pipeline.

    flow source -> windower -> features -> calibrated model -> threshold -> alert

The package is arranged so that training and inference share every step from
windowing onward.  There is one feature implementation, one window geometry, and
one alert schema; the train path and the predict path differ only in which end of
the pipeline they attach to.

===================  ==========================================================
Module               Responsibility
===================  ==========================================================
``features``         window geometry and the feature contract (single source)
``streaming``        incremental windower with bounded buffers
``sources``          Zeek conn.log / JSON / PCAP replay / TShark adapters
``model``            artifact persistence, loading, scoring
``alert``            standardized alert schema, severity, evidence
===================  ==========================================================

Entry points live one level up: ``src/train_portscan.py`` and
``src/predict_portscan.py``.
"""

from __future__ import annotations

__all__ = ["features", "streaming", "sources", "model", "alert"]
