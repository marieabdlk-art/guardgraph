# GuardGraph

**GuardGraph** is a structural AppSec risk detector for web applications and APIs.

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

| Public name | Internal metric | Meaning |
|---|---|---|
| Слепой переход | `PUBLIC_MUTATION` | State-changing endpoint without visible authentication |
| Чужой паспорт | `MISSING_OWNERSHIP_BOUNDARY` | User-controlled resource ID without visible ownership check |
| Голый провод | `RAW_INPUT_TO_SINK` | Raw input reaches SQL/sensitive sink without safe handling |
| Кнопка без крышки | `CRITICAL_ACTION_WEAK_ZONE` | Payment/admin action exposed without strong permission boundary |
| Открытая форма | `PUBLIC_ACTION_UNVALIDATED` | Legit public action without visible validation |

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
python -m guardgraph --config guardgraph.yml
```

Or run directly against a target path:

```bash
python -m guardgraph tests/test_app -o guardgraph_report.json -m guardgraph_report.md
```

## Run tests

```bash
pip install -e .[dev]
pytest
```

## GitHub Actions

The included workflow runs GuardGraph from `guardgraph.yml`, prints the Markdown report in logs, adds it to the Actions summary, uploads JSON/Markdown artifacts, and posts/updates a GuardGraph comment on pull requests.

## Why not just Semgrep / taint tracking?

Classic taint tracking asks:

> Can untrusted input reach a dangerous sink?

GuardGraph asks:

> Given what this endpoint does, which security obligations must exist, and are they visible in the code path?

That makes access-control and ownership gaps first-class findings rather than incidental patterns.

## Config-mode smoke test

This line exists only to verify the config-driven workflow path.
