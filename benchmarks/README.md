# GuardGraph Public Vulnerability Benchmark

This benchmark is designed to test GuardGraph on real public vulnerability cases where the root cause is a missing or weak security boundary around a sensitive application action.

GuardGraph is not evaluated here as a proof-of-exploit scanner. It is evaluated for **structural recall**:

> Does the vulnerable code contain a missing/weak boundary that GuardGraph can identify as a structural AppSec risk?

A successful detection means that GuardGraph found a relevant structural gap on the vulnerable snapshot. It does **not** mean GuardGraph independently proves exploitability.

---

## Scope

Good benchmark candidates:

- missing authentication on sensitive endpoint
- missing authorization / permission boundary
- missing ownership check / IDOR
- public state mutation
- unrestricted upload or unsafe file action without boundary
- raw user-controlled input reaching a sensitive sink

Out-of-scope as primary benchmark cases:

- dependency-only CVEs
- library default configuration bugs
- cryptographic implementation bugs
- memory corruption
- pure infrastructure misconfiguration
- vulnerabilities where source code and fixed commit are not available

---

## Case statuses

| Status | Meaning |
|---|---|
| `candidate` | Public vulnerability looks relevant, but has not yet been reproduced with GuardGraph |
| `reproduced` | Vulnerable snapshot can be checked out and scanned |
| `detected` | GuardGraph finds the expected structural gap |
| `partial` | GuardGraph finds a nearby structural risk but not the exact expected signal |
| `missed` | GuardGraph does not detect the expected structural gap |
| `out_of_scope` | Case is not a fit for GuardGraph's current model |

---

## Benchmark table

| Case | Project | Framework | Class | CWE | Expected GuardGraph signal | Status |
|---|---|---|---|---|---|---|
| CVE-2026-4505 | DB-GPT | FastAPI | unrestricted upload / improper access control | CWE-284, CWE-434 | `CRITICAL_ACTION_WEAK_ZONE`, `PUBLIC_ACTION_UNVALIDATED` | candidate |

---

## Reproducibility requirements

Each confirmed benchmark case should include:

1. public advisory or CVE link
2. vulnerable repository
3. vulnerable version / commit / tag
4. fixed version / commit / tag where possible
5. affected file and symbol
6. expected GuardGraph metric
7. actual GuardGraph JSON/Markdown/SARIF output
8. result classification: `detected`, `partial`, `missed`, or `out_of_scope`

---

## Planned workflow

```bash
python benchmarks/run_benchmark.py --case CVE-2026-4505
```

Expected future output:

```text
case: CVE-2026-4505
status: detected
expected: CRITICAL_ACTION_WEAK_ZONE
found: CRITICAL_ACTION_WEAK_ZONE
report: benchmarks/results/CVE-2026-4505/guardgraph_report.md
```

---

## Interpretation

GuardGraph findings are structural review signals. For benchmark purposes:

- `detected` means the vulnerable version exposes a security-boundary gap matching GuardGraph's model.
- `partial` means GuardGraph surfaces a relevant risk but not the full known vulnerability pattern.
- `missed` means GuardGraph currently lacks the required framework resolver, interprocedural analysis, or heuristic.

This benchmark should be used to guide development, not to overstate exploit-confirmation capability.
