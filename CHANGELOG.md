# Changelog

## v0.3.0 — Reusable GuardGraph Action

GuardGraph `v0.3.0` turns the MVP into a reusable GitHub Action for structural AppSec review of Python/FastAPI applications.

### Added

- Reusable composite GitHub Action via `action.yml`.
- Stable action reference:

  ```yaml
  uses: marieabdlk-art/guardgraph@v0.3.0
  ```

- Config-driven scan mode through `guardgraph.yml`.
- CLI entrypoint:

  ```bash
  python -m guardgraph --config guardgraph.yml
  ```

- Markdown report generation.
- JSON report generation.
- GitHub Actions job summary output.
- Pull Request comment publishing and updating.
- Artifact upload for JSON and Markdown reports.
- Support for direct target mode:

  ```yaml
  with:
    target-path: app
  ```

### Detection scope

Current MVP focuses on structural security gaps in Python/FastAPI applications:

| Public name | Internal metric | Meaning |
|---|---|---|
| Слепой переход | `PUBLIC_MUTATION` | State-changing endpoint without visible authentication |
| Чужой паспорт | `MISSING_OWNERSHIP_BOUNDARY` | User-controlled resource ID without visible ownership check |
| Голый провод | `RAW_INPUT_TO_SINK` | Raw input reaches SQL/sensitive sink without safe handling |
| Кнопка без крышки | `CRITICAL_ACTION_WEAK_ZONE` | Payment/admin action exposed without strong permission boundary |
| Открытая форма | `PUBLIC_ACTION_UNVALIDATED` | Legit public action without visible validation |

### Legit public actions

GuardGraph now distinguishes intentionally public endpoints from dangerous public mutations:

- `USER_REGISTRATION_ACTION`
- `AUTH_SESSION_ACTION`
- `PASSWORD_RESET_ACTION`
- `PUBLIC_CONTACT_ACTION`
- `SEARCH_ACTION`

### CI behavior

On Pull Requests, GuardGraph can now:

1. run tests and structural analysis;
2. generate JSON and Markdown reports;
3. add the Markdown report to the workflow summary;
4. upload reports as artifacts;
5. create or update a PR comment with the report.

### Example workflow

```yaml
name: GuardGraph

on:
  pull_request:
  workflow_dispatch:

permissions:
  contents: read
  issues: write
  pull-requests: write

jobs:
  guardgraph:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Run GuardGraph
        uses: marieabdlk-art/guardgraph@v0.3.0
        with:
          config-path: guardgraph.yml
          pr-comment: "true"
          upload-artifacts: "true"
```

### Limitations

- Python/FastAPI only.
- Static heuristic analysis, not proof of exploitability.
- Intra-project AST-based analysis; deeper interprocedural tracking is planned.
- Findings are structural risk zones and require review in code context.

### Recommended next steps

- Add SARIF output.
- Add configurable thresholds.
- Add framework plugins for Flask, Django, Express, and Next.js APIs.
- Add interprocedural data flow and service-layer tracking.
- Add richer ownership-check recognition.
