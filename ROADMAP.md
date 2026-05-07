# GuardGraph Roadmap

GuardGraph is currently a FastAPI-focused structural AppSec review action. The next phase is about turning the MVP into a more adoptable, integrated, and trustworthy security tool.

## Current status

Implemented in `v0.4.0`:

- FastAPI endpoint analysis.
- Structural gap findings for auth, ownership, raw input to sink, and critical actions.
- English finding titles with optional display labels.
- Review-oriented metadata:
  - `review_required: true`
  - `exploit_confirmed: false`
  - `evidence_strength: STRONG | PARTIAL`
- JSON report.
- Markdown report.
- SARIF 2.1.0 output.
- Reusable GitHub Action.
- Pull Request comments.
- Artifact upload.

---

## Layer 1 — Framework coverage

**Why this matters:** adoption is blocked if GuardGraph only works on FastAPI.

The three-graph architecture is framework-agnostic, but the input layer needs framework-specific resolvers.

### Priority frameworks

1. **Flask**
2. **Django / Django REST Framework**

### Flask resolver targets

Detect:

- `@app.route(...)`
- `Blueprint.route(...)`
- `@login_required`
- custom auth decorators
- `before_request`
- `flask_login.current_user`
- request input from `request.args`, `request.form`, `request.json`, `request.headers`
- resource IDs in route params
- SQL / ORM / filesystem / external side-effect sinks

### Django / DRF resolver targets

Detect:

- function-based views
- class-based views
- `LoginRequiredMixin`
- `@login_required`
- `@permission_required`
- DRF `APIView`
- DRF `ViewSet`
- `permission_classes`
- `authentication_classes`
- serializer validation
- queryset filtering by user / tenant / owner
- `get_object()` and object-level permission patterns

### Target outcome

GuardGraph should support:

```yaml
target:
  framework: fastapi | flask | django
```

---

## Layer 2 — SARIF integration

**Why this matters:** integration is blocked without SARIF and code-scanning compatibility.

Status in `v0.4.0`:

- SARIF 2.1.0 output exists.
- Action can generate SARIF artifact via `sarif-output`.

Next steps:

- Add optional GitHub Code Scanning upload example.
- Validate SARIF with GitHub code scanning.
- Improve SARIF locations for multi-step flows.
- Add rule metadata aligned with OWASP categories.

Example future workflow:

```yaml
- name: Run GuardGraph
  uses: marieabdlk-art/guardgraph@v0.4.0
  with:
    config-path: guardgraph.yml
    sarif-output: guardgraph_report.sarif

- name: Upload SARIF
  uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: guardgraph_report.sarif
```

---

## Layer 3 — Public vulnerability benchmark

**Why this matters:** trust is blocked until GuardGraph demonstrates that it finds real historical vulnerabilities or vulnerability-like patterns.

### Benchmark target

Create a small, reproducible benchmark with 5–10 public cases involving:

- IDOR / missing ownership check
- broken access control
- missing authentication on state mutation
- unsafe raw input to sensitive sink
- dangerous admin/payment/destructive action without strong permission boundary

### Benchmark format

Each case should include:

| Field | Meaning |
|---|---|
| Project | Public repository or minimal reproduced case |
| Vulnerability class | OWASP / CWE / CVE if available |
| Vulnerable commit | Known vulnerable revision |
| Fixed commit | Patch revision, if available |
| Expected finding | GuardGraph metric |
| Result | detected / missed / partial |
| Notes | false positives / limitations |

### Minimum README proof

Add a short benchmark section:

```md
## Benchmark

GuardGraph was evaluated on N public vulnerability cases involving broken access control and missing ownership boundaries.

Detected: X/N
Partial: Y/N
Missed: Z/N
```

---

## Layer 4 — Metric naming and OWASP alignment

**Why this matters:** Russian display labels are memorable, but international AppSec users expect standard terminology.

Status in `v0.4.0`:

- Findings now have English `title` fields.
- Russian labels are kept as `name` / display labels.
- SARIF uses English titles.

### Current mapping

| English title | Display label | Internal metric | OWASP-aligned category |
|---|---|---|---|
| Unguarded State Change | Слепой переход | `PUBLIC_MUTATION` | Broken Access Control |
| Missing Ownership Boundary | Чужой паспорт | `MISSING_OWNERSHIP_BOUNDARY` | IDOR / Broken Access Control |
| Raw Input to Sensitive Sink | Голый провод | `RAW_INPUT_TO_SINK` | Injection / Unsafe Data Handling |
| Critical Action Without Guard | Кнопка без крышки | `CRITICAL_ACTION_WEAK_ZONE` | Broken Access Control |
| Unvalidated Public Entry | Открытая форма | `PUBLIC_ACTION_UNVALIDATED` | Input Validation / Abuse Protection |

### Next steps

- Add `owasp_category` to each finding.
- Add `cwe` where reasonably inferable.
- Use English titles in README, Markdown, SARIF, and GitHub summaries.
- Keep display labels as optional flavor, not the primary AppSec vocabulary.

---

## Proposed version plan

### v0.4.x — Integration polish

- Validate SARIF against GitHub Code Scanning.
- Add Code Scanning workflow example.
- Add OWASP/CWE metadata to findings.
- Improve README positioning: “Structural AppSec Review Action for FastAPI”.

### v0.5.0 — Flask support

- Flask route extraction.
- Flask auth decorator detection.
- Flask request input extraction.
- Flask smoke-test app and tests.

### v0.6.0 — Django / DRF support

- Django URL/view resolver.
- DRF permission class detection.
- Serializer validation detection.
- Object-level permission and queryset ownership heuristics.

### v0.7.0 — Public benchmark

- 5–10 public cases.
- Reproducible benchmark runner.
- README benchmark table.
- Known limitations section.

---

## Product positioning

GuardGraph should be described as:

> A structural AppSec review action that detects missing security boundaries around sensitive application actions.

Not as:

> A proof-of-exploit vulnerability scanner.

GuardGraph findings are review-oriented structural risk zones. They should reduce AppSec review effort, not replace manual validation.
