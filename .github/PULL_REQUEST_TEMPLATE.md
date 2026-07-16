## Summary

- What changed:
- Why it changed:

## Validation

```bash
# Commands run
```

## Evidence Model

- Does this change affect impact verdicts, CVE support levels, or confidence
  reasoning?
- If yes, explain how Evidence Observed / Not Observed / Confidence Drivers /
  Confidence Reducers are preserved.

## Retrieval / Evaluation Impact

- Does this change affect NOVA-F retrieval, index construction, holdout data, or
  evaluation metrics?
- If yes, include the dataset, sample count, index version, model version, and
  exact evaluation command.

## Runtime Artifact Check

Confirm these were not committed:

- `logs/`
- `reports/`
- `data/live/`
- `data/tmp/`
- `data/index/`
- real PCAP files
- raw DataCon datasets
- model weights or private embeddings

## Documentation

- [ ] README / README_EN updated if user-facing behavior changed
- [ ] `docs/API.md` updated if HTTP behavior changed
- [ ] `docs/ARCHITECTURE.md` updated if module boundaries changed
- [ ] Deployment docs updated if operational behavior changed
