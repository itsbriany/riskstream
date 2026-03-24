# Implementation Notes

## Objective

Harden the threat-signal normalizer against the integration failure observed in `local-dev`.

## Approach

- Add a bounded retry to `read_json_object` when MinIO returns `NoSuchKey` for a just-written raw artifact.
- Keep the change narrow and local to the raw-read path.
- Add a unit test that verifies a transient `NoSuchKey` is retried and then succeeds.

## Files Changed

- `riskstream/services/normalization/threat-signal/src/normalizer.py`
- `riskstream/tests/unit/test_threat_signal_normalizer.py`

## Assumptions

- The existing failed integration job represents a real storage-visibility race rather than a stale or unrelated environment error.
- Retrying `NoSuchKey` for a short window is acceptable for this batch normalizer path.

## Risks

- The in-cluster rerun has not yet been completed, so cluster-only behavior still needs confirmation.

## Open Questions

- Whether the cluster integration script can be run from this environment without an interactive sudo-capable path for `k3s ctr images import`.
