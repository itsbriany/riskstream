# Implementation Notes

## Objective

Harden the threat-signal normalizer against the integration failure observed in `local-dev`.

## Approach

- Add a bounded retry to `read_json_object` when MinIO returns `NoSuchKey` for a just-written raw artifact.
- Keep the change narrow and local to the raw-read path.
- Add a unit test that verifies a transient `NoSuchKey` is retried and then succeeds.
- Narrow the `local-dev` MinIO Service to the managed `minio` deployment so integration tests do not hit split object-store backends.

## Files Changed

- `riskstream/services/normalization/threat-signal/src/normalizer.py`
- `riskstream/tests/unit/test_threat_signal_normalizer.py`
- `k8s/overlays/local-dev/minio-patch.yaml`
- `k8s/overlays/local-dev/minio-service-patch.yaml`
- `k8s/overlays/local-dev/kustomization.yaml`

## Assumptions

- The existing failed integration job represents a real storage-visibility race rather than a stale or unrelated environment error.
- Retrying `NoSuchKey` for a short window is acceptable for this batch normalizer path.
- The duplicate `local-minio` and `minio` deployments are a `local-dev` environment issue, so the service-selector fix should stay local-dev-only.

## Risks

- The `local-dev` overlay now depends on the added MinIO label remaining on the managed `minio` deployment template.

## Open Questions

- Whether the stale `local-minio` deployment should be removed entirely in a separate cleanup change rather than merely excluded from the `minio` Service.
