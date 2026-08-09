## Draugr — ❌ FAIL

**Release:** draugr-demo 1.0

| Priority | P1 | P2 | P3 | P4 |
|---|---|---|---|---|
| Findings | 49 | 93 | 77 | 0 |

### Controls

| Control | Verdict | Critical | High | Medium | Low |
|---|---|---:|---:|---:|---:|
| iac | pass | 0 | 0 | 0 | 0 |
| images | **FAIL** | 9 | 40 | 93 | 77 |
| licenses | pass | 0 | 0 | 0 | 0 |
| sast | pass | 0 | 0 | 0 | 0 |
| sca | pass | 0 | 0 | 0 | 0 |
| secrets | pass | 0 | 0 | 0 | 0 |

**Scanned**

- `https://github.com/draugr-dev/draugr.git` at `9590fea8` — 11 uncommitted files not included

### Components

| Component | Verdict | P1 | P2 | P3 | P4 | Failing controls |
|---|---|---:|---:|---:|---:|---|
| api | **FAIL** | 49 | 93 | 77 | 0 | images |
| platform | pass | 0 | 0 | 0 | 0 | - |

_SBOM: 1 document (cyclonedx-json)._

### Fix first

| Priority | Severity | Score | Rule | Control | Scanner | Component | Location |
|---|---|---|---|---|---|---|---|
| P1 | critical | 9.8 | `CVE-2026-42010` | images | Trivy | api | python:3.8-slim |
| P1 | critical | 9.8 | `CVE-2026-31789` | images | Trivy | api | python:3.8-slim |
| P1 | critical | 9.8 | `CVE-2026-8376` | images | Trivy | api | python:3.8-slim |
| P1 | critical | 9.8 | `CVE-2023-45853` | images | Trivy | api | python:3.8-slim |
| P1 | critical | 9.5 | `CVE-2026-57433` | images | Trivy | api | python:3.8-slim |
| P1 | critical | 9.1 | `CVE-2026-33845` | images | Trivy | api | python:3.8-slim |
| P1 | critical | 9.1 | `CVE-2025-7458` | images | Trivy | api | python:3.8-slim |
| P1 | critical | 9.1 | `CVE-2026-13221` | images | Trivy | api | python:3.8-slim |
| P1 | critical | 9.1 | `CVE-2026-42496` | images | Trivy | api | python:3.8-slim |
| P1 | high | 8.8 | `CVE-2024-6345` | images | Trivy | api | python:3.8-slim |
| P1 | high | 8.4 | `CVE-2026-57432` | images | Trivy | api | python:3.8-slim |
| P1 | high | 8.2 | `CVE-2025-32988` | images | Trivy | api | python:3.8-slim |
| P1 | high | 8.2 | `CVE-2025-32990` | images | Trivy | api | python:3.8-slim |
| P1 | high | 8.1 | `CVE-2026-28387` | images | Trivy | api | python:3.8-slim |
| P1 | high | 8.1 | `CVE-2023-31484` | images | Trivy | api | python:3.8-slim |
| P1 | high | 8.0 | `CVE-2026-53615` | images | Trivy | api | python:3.8-slim |
| P1 | high | 8.0 | `CVE-2026-54369` | images | Trivy | api | python:3.8-slim |
| P1 | high | 8.0 | `CVE-2025-59375` | images | Trivy | api | python:3.8-slim |
| P1 | high | 8.0 | `CVE-2026-56408` | images | Trivy | api | python:3.8-slim |
| P1 | high | 8.0 | `CVE-2026-33846` | images | Trivy | api | python:3.8-slim |
| P1 | high | 8.0 | `CVE-2026-42009` | images | Trivy | api | python:3.8-slim |
| P1 | high | 8.0 | `CVE-2025-31115` | images | Trivy | api | python:3.8-slim |
| P1 | high | 8.0 | `CVE-2025-6020` | images | Trivy | api | python:3.8-slim |
| P1 | high | 8.0 | `CVE-2025-15467` | images | Trivy | api | python:3.8-slim |
| P1 | high | 8.0 | `CVE-2026-45447` | images | Trivy | api | python:3.8-slim |

_…and 194 more finding(s)._
