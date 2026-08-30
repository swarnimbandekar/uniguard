# C2 Beaconing Detector — Model Card / Metric Brief

**Component:** c2_beaconing_detector v1.0.0
**Threat class:** C2_BEACONING · **Mode:** passive, read-only, metadata-only (no payload/decryption)
**Model:** HistGradientBoosting (max_iter=200, lr=0.1, class_weight=balanced, RNG=0), 13 behavioral features
**Architecture:** two independent timescales, no score fusion

## Evaluation discipline
Temporal split with embargo; preprocessing fit on TRAIN only; threshold set on VALIDATION only;
test scored EXACTLY ONCE. No endpoint identity (IP/port/uid) is ever a feature. Data: CTU-13
capture-50 (Neris), native full-network Zeek conn.log.

## Headline metrics (temporal held-out, scored once)
| Detector      | Precision | Recall | F1   | PR-AUC | Seq-recall | Throughput      |
|---------------|-----------|--------|------|--------|------------|-----------------|
| Fast 60s/10s  | 0.589     | 0.725  | 0.65 | 0.70   | 1.00       | ~318 flows/s (~75 Mbps) |
| Deep 300s/60s | 0.797     | 0.625  | 0.70 | 0.72   | 0.83       | ~504 flows/s (~119 Mbps) |

**Seq-recall** = fraction of actual C2 channels caught at least once (the operationally
meaningful number). Accuracy is ~99.6% but meaningless here (≈130:1 class imbalance) — judge on PR-AUC/recall.

### Confusion matrices
Fast 60s/10s (thr 0.480): TP=3,933 · FP=2,742 · FN=1,495 · TN=724,466
Deep 300s/60s (thr 0.975): TP=987 · FP=251 · FN=592 · TN=442,030

## Scope & honest limitations (read before deploying)
- **Strong on beaconing patterns it has seen the shape of** (same-family). Catches periodic,
  low-jitter C2 channels well.
- **Cross-family generalization is WEAK.** Held-out unseen families (Virut, Menti) pooled
  PR-AUC ~0.06–0.07. This is a supplementary binetflow study (Argus flows, not native Zeek)
  and is not directly comparable, but the signal is clear: do not sell as family-agnostic.
- **Novel-endpoint slice fails** (P≈0.09): it does not reliably flag arbitrary unseen C2 endpoints.
- Trained on one network (CVUT /16). Not yet validated cross-network.

## Recommended framing to the lead
Ship as the C2 detector for known beaconing behavior, running alongside the other five
detectors as a defense-in-depth layer. It is a real, validated, streaming module with a
standardized alert contract — not a universal C2 oracle. Value is highest when correlated
with the other detectors, not as a sole verdict.
