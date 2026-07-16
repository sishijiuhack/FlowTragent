# Changelog

All notable changes to FlowTragent will be documented in this file.

The format follows Keep a Changelog style, and this project uses date-based
pre-release entries until formal version tags are introduced.

## Unreleased

### Added

- DataCon index build and holdout evaluation workflow with quality gates.
- Zeek, Suricata EVE, endpoint, and application log ingestion paths.
- Expanded DNS/TCP/ICMP detection and attack marker coverage.
- Cross-window attack activity correlation for live alerts.
- Prometheus `/metrics` endpoint.
- Structured JSON Lines audit logging.
- Webhook notification channel with fingerprint-based suppression.
- Unified deployment guidance for systemd, Docker/Compose, and log rotation.

### Changed

- Retrieval evaluation now emphasizes reproducible index versions, holdout
  separation, and leakage prevention rather than a single recall number.
- Host-side endpoint/application evidence can raise post-exploitation
  confidence, while ordinary endpoint noise does not bypass HTTP 4xx downgrade.

### Known Limitations

- Docker Compose static configuration is available, but real
  `docker compose up --build` still needs verification when Docker daemon is
  running.
- Local DataCon data currently remains below the planned >=10,000 sample scale;
  the engineering evaluation loop is ready for a larger dataset.
- Windows test runs skip scapy-dependent real PCAP parsing when scapy is absent.
