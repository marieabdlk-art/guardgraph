# Changelog

All notable changes to GuardGraph are documented here.

## v0.4.3

### Added

- FastAPI Dependency Injection benchmark.
- Support for `CurrentUser`-style dependency aliases.
- Support for keyword-only FastAPI endpoint parameters after `*`.
- Real-project smoke scan workflow against `fastapi/full-stack-fastapi-template`.
- Explicit `guardgraph/graphs.py` architecture module for the three conceptual graph layers:
  - `DataExposureGraph`
  - `AccessBoundaryGraph`
  - `StateMutationGraph`

### Changed

- Reduced false positives on protected FastAPI endpoints using `Depends(...)`, `Annotated[..., Depends(...)]`, and route-level dependencies.
- Updated README examples to use `marieabdlk-art/guardgraph@v0.4.3`.
- Updated package version to `0.4.3`.

### Validation

Real-project scan on `fastapi/full-stack-fastapi-template/backend/app`:

- endpoints found: 23
- critical/high findings on protected `CurrentUser` endpoints: 0
- remaining findings: 2 medium public-entry review notes

## v0.4.2

### Added

- Upload/plugin boundary detection concept through `UNRESTRICTED_UPLOAD_BOUNDARY`.
- Static-analysis benchmark fixture for upload boundary regression tests.
- OWASP/CWE mapping for upload boundary findings.

## v0.4.1

### Added

- OWASP category metadata for findings.
- CWE metadata for findings.
- Markdown report rendering of OWASP/CWE metadata.
- SARIF rule/result metadata for OWASP/CWE fields.
- GitHub Code Scanning example in README.

## v0.4.0

### Added

- SARIF output support.
- Professional English finding titles alongside display labels.
- Review-oriented finding fields:
  - `review_required`
  - `exploit_confirmed`
  - `evidence_strength`

## v0.3.0

### Added

- Reusable GitHub Action support.
- JSON and Markdown report generation.
- Pull request comment output.
- Artifact upload support.

## v0.2.0

### Added

- Threefold structural gap analysis MVP for FastAPI.
- Initial detection classes:
  - `PUBLIC_MUTATION`
  - `MISSING_OWNERSHIP_BOUNDARY`
  - `RAW_INPUT_TO_SINK`
  - `CRITICAL_ACTION_WEAK_ZONE`
  - `PUBLIC_ACTION_UNVALIDATED`

## v0.1.0

### Added

- Initial GuardGraph prototype.
