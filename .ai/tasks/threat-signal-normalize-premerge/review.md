# Review Findings

## Resolved Blocking Finding

1. The integration workflow had a concrete resilience gap: the normalizer read path failed hard on transient `NoSuchKey` immediately after a raw artifact was written, even though the test client could already observe the object. This blocked the in-cluster test job and made the batch path too brittle for just-written artifacts.

## What Looks Good

- The branch is aligned with the roadmap's Phase 1 goal of introducing a common normalized threat-signal contract without adding major new platform components.
- The URLhaus parsing change preserves commented CSV headers, which matches the observed feed shape and protects downstream normalization.
- The unit test surface covers schema validity, key layout, delta action mapping, and normalized write behavior.

## Remaining Concerns

- The integration rerun is still required to prove the fix in the real cluster path.
- The tester is currently blocked from importing the rebuilt image into k3s because `sudo k3s ctr images import -` requires an interactive password in this environment.

## Reviewer Checklist Summary

- Security and OWASP Top 10: no obvious new application-layer findings surfaced in the reviewed paths.
- Data corruption: no new corruption path identified after the raw-read retry hardening; normalized writes remain append-style object writes.
- Crash and undefined behavior: the resolved raw-read race was the clearest crash trigger in the tested path.
- Logging and observability: existing JSON error logging on normalization failure is adequate for the current batch path.
- Cost and resource creep: no new obvious storage, memory, or compute regressions surfaced in the reviewed code change itself; scheduled normalization frequency should still be monitored in cluster.
