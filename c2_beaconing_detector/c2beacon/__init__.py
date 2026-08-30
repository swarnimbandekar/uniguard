"""c2beacon — passive C2-beaconing window feature extractor.

Phase: feature extraction (post data-audit). Implements ONLY the 7 essential
features approved in ``_audit_work/results/FEATURE_SPEC.md``. No model, no
threshold, no positivity rule, and no window size are decided here.
"""
from .features import (
    extract,
    extract_window,
    StreamingWindowExtractor,
    feature_matrix,
    iat_seconds,
    FEATURE_COLUMNS,
    KEY_COLUMNS,
    DEFAULT_SUBBINS,
    NO_PORT,
)
from .sources import (
    read_zeek_conn_log,
    normalize_zeek_conn,
    normalize_binetflow,
    ensure_datetime,
    NORMALIZED_COLUMNS,
)

__all__ = [
    "extract",
    "extract_window",
    "StreamingWindowExtractor",
    "feature_matrix",
    "iat_seconds",
    "FEATURE_COLUMNS",
    "KEY_COLUMNS",
    "DEFAULT_SUBBINS",
    "NO_PORT",
    "read_zeek_conn_log",
    "normalize_zeek_conn",
    "normalize_binetflow",
    "ensure_datetime",
    "NORMALIZED_COLUMNS",
]
