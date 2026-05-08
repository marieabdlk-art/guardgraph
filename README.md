# GuardGraph

**GuardGraph** is a structural AppSec review action for FastAPI applications.

Traditional scanners usually search for known dangerous patterns: unsafe functions, vulnerable dependencies, suspicious calls, or source-to-sink flows.

GuardGraph looks for a different class of risk: **missing security boundaries around sensitive application actions**.

For every endpoint, GuardGraph asks:

1. What does this endpoint do?
2. What data does it accept?
3. What resource does it access or mutate?
4. What security obligations should protect this action?
5. Are those protections visible in the code path?

GuardGraph builds three structural views:

- **Data Exposure Graph** — user-controlled input, validation, and sensitive sinks.
- **Access Boundary Graph** — authentication, authorization, ownership, and role checks.
- **State Mutation Graph** — writes, deletes, payments, admin operations, uploads, and external side effects.

Then it performs **Threefold Structural Gap Analysis**:

> sensitive action + required protection missing or not visible = structural risk

GuardGraph does **not** claim that every finding is a confirmed exploit. It reports explainable structural risk zones that deserve review before they become vulnerabilities.

## MVP scope

Current MVP focuses on **Python + FastAPI**.

Detected structural gaps:

| English title | Display label | Internal metric | OWASP / CWE | Meaning |
|---|---|---|---|---|
| Unguarded State Change | Слепой переход | `PUBLIC_MUTATION` | A01 / CWE-862, CWE-306 | State-changing endpoint without visible authentication |
| Missing Ownership Boundary | Чужой паспорт | `MISSING_OWNERSHIP_BOUNDARY` | A01 / CWE-639, CWE-862 | User-controlled resource ID without visible ownership check |
| Raw Input to Sensitive Sink | Голый провод | `RAW_INPUT_TO_SINK` | A03 / CWE-89, CWE-20 | Raw input reaches SQL/sensitive sink without safe handling |
| Critical Action Without Guard | Кнопка без крышки | `CRITICAL_ACTION_WEAK_ZONE` | A01 / CWE-862, CWE-732 | Payment/admin action exposed without strong permission boundary |
| Unvalidated Public Entry | Открытая форма | `PUBLIC_ACTION_UNVALIDATED` | A04 / CWE-20, CWE-770 | Legit public action without visible validation |
| Unsafe Upload Boundary | Открытая загрузка | `UNRESTRICTED_UPLOAD_BOUNDARY` | A01 / CWE-434, CWE-284 | Upload/plugin action without visible upload-specific boundaries |

Each finding includes:

- `review_required: true`
- `exploit_confirmed: false`
- `evidence_strength: STRONG | PARTIAL`
- `owasp_category`
- `cwe`

## FastAPI Dependency Injection benchmark

GuardGraph includes a focused FastAPI Dependency Injection benchmark covering:

- direct `Depends(get_current_user)`
- `Annotated[..., Depends(...)]`
- route-level `dependencies=[Depends(...)]`
- router-level `dependencies=[Depends(...)]`
- nested admin-style dependencies
- dependency aliases such as `CurrentUser = Annotated[..., Depends(get_current_user)]`
- keyword-only FastAPI endpoint parameters after `*`
- legitimate public actions such as registration

The benchmark checks that protected endpoints are not reported as missing authentication, while an intentionally unprotected control endpoint is reported.

GuardGraph v0.4.3 was also smoke-tested against `fastapi/full-stack-fastapi-template` on `backend/app`:

- endpoints found: 23
- critical/high findings on protected `CurrentUser` endpoints: 0
- remaining findings: 2 medium public-entry review notes

## Legitimate public actions

GuardGraph distinguishes dangerous public mutations from legitimate unauthenticated actions:

- `USER_REGISTRATION_ACTION`
- `AUTH_SESSION_ACTION`
- `PASSWORD_RESET_ACTION`
- `PUBLIC_CONTACT_ACTION`

These should not require `AUTH_REQUIRED`. They should have validation and abuse/rate-limit protections.

## Configuration

GuardGraph can be configured through `guardgraph.yml`:

```yaml
target:
  path: "tests/test_app"
  language: "python"
  framework: "fastapi"

report:
  json: "guardgraph_report.json"
  markdown: "guardgraph_report.md"

github:
  pr_comment: true
```

## Quick start

Run with the config file:

```bash
python -m guardgraph --config guardgraph.yml --sarif guardgraph_report.sarif
```

Or run directly against a target path:

```bash
python -m guardgraph tests/test_app -o guardgraph_report.json -m guardgraph_report.md --sarif guardgraph_report.sarif
```

## Reusable GitHub Action

GuardGraph can be used as a reusable GitHub Action from another repository:

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
        uses: marieabdlk-art/guardgraph@v0.4.3
        with:
          config-path: guardgraph.yml
          pr-comment: "true"
          upload-artifacts: "true"
          sarif-output: guardgraph_report.sarif
```

Direct target mode is also supported:

```yaml
- name: Run GuardGraph
  uses: marieabdlk-art/guardgraph@v0.4.3
  with:
    target-path: app
    json-output: guardgraph_report.json
    markdown-output: guardgraph_report.md
    sarif-output: guardgraph_report.sarif
    pr-comment: "true"
```

## GitHub Code Scanning example

GuardGraph can generate SARIF and upload it to GitHub Code Scanning:

```yaml
name: GuardGraph Code Scanning

on:
  pull_request:
  workflow_dispatch:

permissions:
  contents: read
  security-events: write
  pull-requests: write
  issues: write

jobs:
  guardgraph:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Run GuardGraph
        uses: marieabdlk-art/guardgraph@v0.4.3
        with:
          config-path: guardgraph.yml
          pr-comment: "true"
          upload-artifacts: "true"
          sarif-output: guardgraph_report.sarif

      - name: Upload SARIF to GitHub Code Scanning
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: guardgraph_report.sarif
```

## SARIF output

GuardGraph can emit SARIF 2.1.0:

```bash
python -m guardgraph --config guardgraph.yml --sarif guardgraph_report.sarif
```

SARIF results preserve GuardGraph metadata such as risk level, confidence, evidence strength, OWASP category, CWE IDs, review requirement, and the fact that exploitability is not confirmed.

## Run tests

```bash
pip install -e .[dev]
pytest
```

## GitHub Actions

The included workflow uses the local action (`uses: ./`) to run GuardGraph from `guardgraph.yml`, print the Markdown report in logs, add it to the Actions summary, upload JSON/Markdown/SARIF artifacts, and post/update a GuardGraph comment on pull requests.

## Why not just Semgrep / taint tracking?

Classic taint tracking asks:

> Can untrusted input reach a dangerous sink?

GuardGraph asks:

> Given what this endpoint does, which security obligations must exist, and are they visible in the code path?

That makes access-control and ownership gaps first-class findings rather than incidental patterns.
