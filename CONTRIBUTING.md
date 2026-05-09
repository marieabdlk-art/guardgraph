# Contributing to GuardGraph

Thank you for your interest in contributing to GuardGraph.

GuardGraph is an early-stage structural AppSec review tool for FastAPI applications. Contributions are welcome, especially around framework coverage, false-positive reduction, real-project benchmarks, SARIF quality, and documentation.

## How to contribute

1. Open an issue describing the bug, false positive, false negative, or feature request.
2. Fork the repository and create a focused branch.
3. Add or update tests when changing detection behavior.
4. Keep findings explainable: every detection should include clear evidence and a review-oriented recommendation.
5. Open a pull request with a short explanation of the change and the expected impact.

## Development setup

```bash
pip install -e .[dev]
pytest
```

## Detection changes

When changing detection logic, please include at least one regression test in `tests/` or a benchmark fixture in `benchmarks/`.

Preferred test coverage includes:

- a positive case where GuardGraph should report a finding;
- a negative case where GuardGraph should not report a finding;
- evidence that common FastAPI Dependency Injection patterns are handled correctly.

## Security model

GuardGraph reports structural review findings, not confirmed exploits.

A finding should be phrased as a reviewable risk zone unless exploitability has been independently confirmed.

## Project scope

Current MVP scope:

- Python
- FastAPI
- GitHub Action usage
- JSON, Markdown, and SARIF reports

Planned areas:

- additional FastAPI patterns;
- Flask/Django support;
- more real-project benchmarks;
- improved SARIF and Code Scanning integration.

## License

By contributing, you agree that your contributions will be licensed under the MIT License.
