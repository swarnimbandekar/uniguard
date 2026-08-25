#!/usr/bin/env python3
"""The trained artifact: what gets persisted, how it loads, how it scores.

A detector that scores well offline and fails in the field usually fails at one of
two seams: the features drift between training and serving, or the preprocessing
does.  ``portscan.features`` closes the first seam by being the single feature
implementation.  This module closes the second: the scaler is fitted and persisted
*inside* the estimator, so ``score`` applies byte-identical preprocessing to what
training applied, and there is no standalone transform step to fall out of sync.

The artifact is one file holding the fitted estimator and everything needed to
prove that the code loading it is the code it was trained under:

* the fitted estimator, scaler included, calibrated
* the feature columns, in the fitted order
* the window geometry (window / stride / min_flows)
* the ``FAILED_STATES`` definition the features were computed under
* the operating threshold
* the calibration method
* a fingerprint of the training corpus
* the scikit-learn version that fitted it

Loading fails loudly
--------------------
Every one of those is checked at load time, because a silent mismatch is the
failure mode this whole structure exists to prevent.  If the running
``features.FEATURE_COLUMNS`` no longer matches the order the model was fitted on,
the feature vector lines up with the wrong coefficients and the scores are
meaningless -- but nothing crashes, so it would ship.  ``load`` raises
``ArtifactMismatch`` instead.  The scikit-learn version is the one exception that
can be downgraded to a warning, because a pickled estimator often loads across a
minor version, but the default is still to refuse: an unpickled model from another
version is not guaranteed to compute what it computed before.

The window geometry is the one persisted field that is *not* an equality check.
It is validated for sanity (positive window/stride, min_flows >= 1) and then taken
as declared, because the serving path builds its windower from the artifact's own
``window_spec`` -- so windows are always cut on the grid the model was fitted at,
whatever that grid is.  Requiring it to equal the module default bought no safety
(nothing reads the default at serve time) and wrongly refused a legitimately
non-default artifact such as the 10s/2s handoff build.

Why confidence must be calibrated
---------------------------------
The alert schema has a ``confidence`` field and a severity derived from it, so
``confidence`` has to be a probability an analyst can read as one.  A raw
``predict_proba`` from a forest is a leaf-vote fraction, not a probability; the
pilot measured a frozen random-forest threshold producing 15,185 false positives
on CTU where a logistic model produced 3, which is exactly what an uncalibrated
score does when carried across networks.  So ``alert_for`` refuses to run on an
uncalibrated artifact unless explicitly forced, and records the calibration method
in every alert's ``detector`` block so the dashboard can see what produced the
number.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable, Sequence

import joblib
import numpy as np
import sklearn

from . import features as fx
from .alert import Alert, build_alert
from .features import Window, WindowSpec

# Bumped only when the on-disk layout changes in a way an older loader could not
# read.  Distinct from the alert schema version: this is the artifact file format,
# that is the wire format to downstream teams.
ARTIFACT_SCHEMA_VERSION = "1.0"

# Calibration methods a confidence field may be built from.  "none" is loadable --
# a diagnostic run may want the raw scores -- but alert construction refuses it.
CALIBRATED_METHODS = frozenset({"isotonic", "sigmoid"})


class ArtifactMismatch(RuntimeError):
    """The loaded artifact disagrees with the code trying to use it.

    Its own type so a caller can distinguish "this model does not match this code"
    from an arbitrary load failure and act on it -- refuse to serve, or fall back
    to retraining -- rather than swallowing every exception the same way.
    """


@dataclass(frozen=True, slots=True)
class TrainingProvenance:
    """Where the artifact came from: corpus fingerprint and environment.

    Recorded, not enforced, except for the scikit-learn version.  A fingerprint
    mismatch does not stop inference -- the same code can serve a model trained on
    a different corpus -- but it is the first thing to check when a deployed
    detector behaves unlike its evaluation, so it travels with the model.
    """

    corpus_fingerprint: str
    corpus_files: tuple[str, ...]
    row_count: int
    positive_count: int
    sklearn_version: str
    created_utc: str
    notes: dict[str, str] = field(default_factory=dict)

    def as_dict(self) -> dict:
        return {
            "corpus_fingerprint": self.corpus_fingerprint,
            "corpus_files": list(self.corpus_files),
            "row_count": self.row_count,
            "positive_count": self.positive_count,
            "sklearn_version": self.sklearn_version,
            "created_utc": self.created_utc,
            "notes": dict(self.notes),
        }


@dataclass(slots=True)
class PortScanDetector:
    """A loaded, ready-to-score detector: estimator plus the contract it was fit under.

    The estimator carries its own scaler, so ``score`` is the whole preprocessing
    and inference path.  Everything else on this object exists to guarantee the
    estimator is being fed what it was trained on.
    """

    estimator: object                      # fitted sklearn estimator, scaler inside
    feature_columns: tuple[str, ...]       # order the estimator was fitted on
    window_spec: WindowSpec
    failed_states: frozenset[str]
    threshold: float
    calibration_method: str
    model_name: str
    provenance: TrainingProvenance

    # ------------------------------------------------------------- persistence

    def save(self, path: str | Path) -> Path:
        """Write the single-file artifact. Model and preprocessing together."""
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        bundle = {
            "schema": ARTIFACT_SCHEMA_VERSION,
            "estimator": self.estimator,
            "feature_columns": list(self.feature_columns),
            "window": self.window_spec.as_dict(),
            "failed_states": sorted(self.failed_states),
            "threshold": float(self.threshold),
            "calibration_method": self.calibration_method,
            "model_name": self.model_name,
            "provenance": self.provenance.as_dict(),
        }
        joblib.dump(bundle, path)
        return path

    @classmethod
    def load(
        cls,
        path: str | Path,
        allow_version_mismatch: bool = False,
    ) -> "PortScanDetector":
        """Load an artifact, validating it against the running code. Fails loudly.

        ``allow_version_mismatch`` downgrades only the scikit-learn version check
        to a warning.  It never relaxes the feature or FAILED_STATES checks: those
        are code-vs-artifact correctness, not compatibility.  The window geometry
        is validated for sanity and then honored as declared (the serving windower
        reads it from the artifact), not required to equal the module default.
        """
        path = Path(path)
        if not path.is_file():
            raise FileNotFoundError(f"No model artifact at {path}")
        bundle = joblib.load(path)

        schema = bundle.get("schema")
        if schema != ARTIFACT_SCHEMA_VERSION:
            raise ArtifactMismatch(
                f"artifact schema {schema!r} != loader schema "
                f"{ARTIFACT_SCHEMA_VERSION!r}; this file was written by a different "
                "version of the component"
            )

        estimator = bundle["estimator"]
        if not hasattr(estimator, "predict_proba"):
            raise ArtifactMismatch(
                "persisted estimator has no predict_proba; a confidence field "
                "cannot be produced from it"
            )

        feature_columns = tuple(bundle["feature_columns"])
        _validate_features(feature_columns)
        _validate_failed_states(bundle["failed_states"])
        window_spec = _validate_window(bundle["window"])
        _validate_sklearn_version(bundle["provenance"]["sklearn_version"],
                                  allow_version_mismatch)

        provenance_fields = bundle["provenance"]
        provenance = TrainingProvenance(
            corpus_fingerprint=provenance_fields["corpus_fingerprint"],
            corpus_files=tuple(provenance_fields["corpus_files"]),
            row_count=provenance_fields["row_count"],
            positive_count=provenance_fields["positive_count"],
            sklearn_version=provenance_fields["sklearn_version"],
            created_utc=provenance_fields["created_utc"],
            notes=dict(provenance_fields.get("notes", {})),
        )
        return cls(
            estimator=estimator,
            feature_columns=feature_columns,
            window_spec=window_spec,
            failed_states=frozenset(bundle["failed_states"]),
            threshold=float(bundle["threshold"]),
            calibration_method=bundle["calibration_method"],
            model_name=bundle["model_name"],
            provenance=provenance,
        )

    # ------------------------------------------------------------------ scoring

    @property
    def is_calibrated(self) -> bool:
        return self.calibration_method in CALIBRATED_METHODS

    def score(self, window: Window) -> float:
        """Calibrated scan probability for one window, in [0, 1]."""
        return float(self.score_many([window])[0])

    def score_many(self, windows: Sequence[Window]) -> np.ndarray:
        """Calibrated probabilities for many windows, one predict_proba call.

        Vectorised because per-window calls dominate inference latency on a busy
        tail, and the metric set measures that latency.  The column order comes
        from the artifact, never from dict iteration order, so a feature added to
        the running code cannot silently shift the vector under a model that was
        fitted before it existed.
        """
        if not windows:
            return np.empty(0, dtype=float)
        matrix = np.array(
            [window.feature_vector(self.feature_columns) for window in windows],
            dtype=float,
        )
        return self.estimator.predict_proba(matrix)[:, 1]

    def is_alert(self, confidence: float) -> bool:
        """Whether a score clears the persisted operating threshold."""
        return confidence >= self.threshold

    def detector_tag(self) -> dict[str, str]:
        """Provenance stamped into every alert's ``detector`` block."""
        return {
            "model": self.model_name,
            "calibration": self.calibration_method,
            "threshold": f"{self.threshold:.4f}",
            "corpus_fingerprint": self.provenance.corpus_fingerprint[:12],
            "sklearn": self.provenance.sklearn_version,
        }

    def alert_for(
        self,
        window: Window,
        require_calibrated: bool = True,
    ) -> Alert | None:
        """Score one window and return an Alert if it clears threshold, else None.

        ``None`` is the normal case -- most windows are not scans -- and is
        distinct from the windower's abstention, which happens earlier and never
        reaches here.  Refuses an uncalibrated artifact by default because the
        resulting ``confidence`` and its severity would be misleading.
        """
        if require_calibrated and not self.is_calibrated:
            raise ArtifactMismatch(
                f"calibration_method={self.calibration_method!r} is not calibrated; "
                "refusing to emit a confidence field. Pass require_calibrated=False "
                "for a diagnostic run that understands the score is uncalibrated."
            )
        confidence = self.score(window)
        if not self.is_alert(confidence):
            return None
        return build_alert(window, confidence, detector=self.detector_tag())

    def alerts_for(
        self,
        windows: Iterable[Window],
        require_calibrated: bool = True,
    ) -> list[Alert]:
        """Batch form of ``alert_for``, sharing one predict_proba call."""
        windows = list(windows)
        if require_calibrated and not self.is_calibrated:
            raise ArtifactMismatch(
                f"calibration_method={self.calibration_method!r} is not calibrated; "
                "refusing to emit confidence fields"
            )
        scores = self.score_many(windows)
        alerts = []
        for window, confidence in zip(windows, scores):
            if self.is_alert(float(confidence)):
                alerts.append(build_alert(window, float(confidence),
                                          detector=self.detector_tag()))
        return alerts


# --------------------------------------------------------------- load-time checks

def _validate_features(columns: tuple[str, ...]) -> None:
    current = tuple(fx.FEATURE_COLUMNS)
    if columns != current:
        raise ArtifactMismatch(
            "feature columns in the artifact do not match the running "
            f"features.FEATURE_COLUMNS.\n  artifact: {list(columns)}\n  code:     "
            f"{list(current)}\nThe feature vector would line up with the wrong "
            "coefficients; retrain or check out the matching code revision."
        )


def _validate_failed_states(states: Sequence[str]) -> None:
    artifact_states = frozenset(states)
    if artifact_states != fx.FAILED_STATES:
        raise ArtifactMismatch(
            "FAILED_STATES in the artifact do not match the running definition.\n"
            f"  artifact: {sorted(artifact_states)}\n  code:     "
            f"{sorted(fx.FAILED_STATES)}\nEvery *_ratio feature would mean something "
            "different than it did at fit time."
        )


def _validate_window(window: dict) -> WindowSpec:
    """Reconstruct the artifact's OWN window geometry and sanity-check it.

    This deliberately does NOT require the geometry to equal the running
    ``WindowSpec()`` default.  The serving path builds its windower from
    ``detector.window_spec`` (see ``predict_portscan.py``), so the artifact's
    declared geometry is authoritative and self-consistent: windows are always cut
    on the grid the model was fitted at, whatever that grid is.  Pinning to the
    module default instead conflated "the code's default geometry" with "this
    artifact's geometry" -- it refused a legitimately-trained non-default artifact
    (the 10s/2s handoff build) while giving no extra protection, because nothing at
    serve time reads the module default.  Feature-column and ``FAILED_STATES``
    validation stay strict: those ARE code-vs-artifact correctness, deciding
    whether the feature vector lines up with the fitted coefficients.
    """
    try:
        spec = WindowSpec(
            window_seconds=float(window["window_seconds"]),
            stride_seconds=float(window["stride_seconds"]),
            min_flows=int(window["min_flows"]),
        )
    except (KeyError, TypeError, ValueError) as error:
        raise ArtifactMismatch(f"artifact window geometry is malformed: {error!r}")
    if not (spec.window_seconds > 0 and spec.stride_seconds > 0 and spec.min_flows >= 1):
        raise ArtifactMismatch(
            f"artifact window geometry is not sane: {spec.as_dict()} "
            "(need window_seconds>0, stride_seconds>0, min_flows>=1)")
    return spec


def _validate_sklearn_version(trained_version: str, allow_mismatch: bool) -> None:
    running = sklearn.__version__
    if trained_version == running:
        return
    message = (
        f"artifact was fitted with scikit-learn {trained_version}, running "
        f"{running}. A pickled estimator is not guaranteed to compute the same "
        "thing across versions."
    )
    if allow_mismatch:
        import warnings
        warnings.warn(message, RuntimeWarning, stacklevel=3)
    else:
        raise ArtifactMismatch(
            message + " Re-fit under the running version, or pass "
            "allow_version_mismatch=True if you have verified compatibility."
        )


# ---------------------------------------------------------------- fingerprinting

def corpus_fingerprint(paths: Sequence[str | Path]) -> str:
    """A stable content hash of the training tables.

    Hashes file bytes in a fixed order so the same corpus always yields the same
    fingerprint and any change to the training data yields a different one.  This
    is what lets a deployed alert be traced back to the exact table it was trained
    on -- the ``detector_tag`` carries the first twelve hex digits.
    """
    digest = hashlib.sha256()
    for path in sorted(str(Path(p).resolve()) for p in paths):
        digest.update(path.encode("utf-8"))
        digest.update(Path(path).read_bytes())
    return digest.hexdigest()


def make_provenance(
    corpus_files: Sequence[str | Path],
    row_count: int,
    positive_count: int,
    notes: dict[str, str] | None = None,
) -> TrainingProvenance:
    """Assemble provenance at training time, stamping version and UTC time."""
    return TrainingProvenance(
        corpus_fingerprint=corpus_fingerprint(corpus_files),
        corpus_files=tuple(Path(p).name for p in corpus_files),
        row_count=row_count,
        positive_count=positive_count,
        sklearn_version=sklearn.__version__,
        created_utc=datetime.now(timezone.utc).isoformat(),
        notes=dict(notes or {}),
    )


if __name__ == "__main__":  # pragma: no cover - smoke check
    import sys

    if len(sys.argv) < 2:
        raise SystemExit("usage: python -m portscan.model <artifact.joblib>")
    detector = PortScanDetector.load(sys.argv[1])
    print(f"model:        {detector.model_name}")
    print(f"calibration:  {detector.calibration_method} "
          f"(calibrated: {detector.is_calibrated})")
    print(f"threshold:    {detector.threshold:.4f}")
    print(f"features:     {len(detector.feature_columns)} "
          f"in fitted order")
    print(f"window:       {detector.window_spec.as_dict()}")
    print(f"failed_states:{sorted(detector.failed_states)}")
    print(f"fingerprint:  {detector.provenance.corpus_fingerprint}")
    print(f"corpus:       {detector.provenance.row_count:,} rows, "
          f"{detector.provenance.positive_count:,} positive "
          f"({', '.join(detector.provenance.corpus_files)})")
    print(f"fitted with:  scikit-learn {detector.provenance.sklearn_version} "
          f"at {detector.provenance.created_utc}")
