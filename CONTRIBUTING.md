# Contributing to `nxtflow`

Thank you for contributing to **`nxtflow`** — the open-source, AI-ready NetFlow v5/v9, IPFIX, and sFlow telemetry platform for Kubernetes, Loki, and Grafana.

---

## 1. Local Development Setup

### Prerequisites
- Python `>= 3.11`
- Helm `v4.x` (for chart linting and template tests)
- Docker (optional, for container builds)

### Create Virtual Environment & Install Dev Dependencies
```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -e ".[mcp,dev]" jsonschema
```

### Build Helm Chart Dependencies
```bash
helm repo add grafana-community https://grafana-community.github.io/helm-charts
helm repo add prometheus-community https://prometheus-community.github.io/helm-charts
helm repo update
helm dependency build charts/nxtflow
```

---

## 2. Running Checks Locally

```bash
# 1. Security, Secret & Syntax Audit
python3 scripts/security_audit.py

# 2. Python Linter
ruff check src tests scripts .github/scripts

# 3. Helm Lint (Default + All Example Modes)
helm lint charts/nxtflow
helm lint charts/nxtflow -f examples/values-standalone.yaml
helm lint charts/nxtflow -f examples/values-integrated.yaml
helm lint charts/nxtflow -f examples/values-collector-only.yaml

# 4. Full Pytest Suite (Python + Helm Schema/Template Tests)
pytest -v
```

---

## 3. Security, Configuration Hygiene & Quality Standards

1. **Clean Example Fixtures & Secret Hygiene:**
   - Never commit real credentials, API tokens, private keys, Slack webhooks, or private production endpoints.
   - Always use RFC 5737 (`192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`), RFC 3849 (`2001:db8::/32`), standard RFC 1918 examples (`192.168.1.0/24`, `10.0.0.0/8`), and RFC 2606 domains (`example.com`) in examples and tests.
2. **Automated CI/CD Verification:**
   - Every pull request runs **Lint, Syntax & Security Audit** (`scripts/security_audit.py`), **Python Lint & Unit Tests** (`ruff` + `pytest`), **Helm Lint, Schema & Template** (`helm lint`, `ct lint`, `tests/test_helm.py`), and **Docker Build & Kind Helm Install** (`kind` + `helm test`).
3. **Read-Only AI Guardrails:**
   - Keep `nxtflow-mcp` strictly read-only, and preserve `validate_range()` (`30d` cap), `clamp_limit()`, and LogQL escaping helpers in `src/nxtflow/config.py`.

---

## 4. Pull Request Workflow

1. Create a feature or fix branch from `main`.
2. Add or update unit/Helm tests under `tests/`.
3. Run `python3 scripts/security_audit.py`, `ruff check src tests scripts .github/scripts`, `helm lint charts/nxtflow`, and `pytest -v`.
4. Open a Pull Request targeting `main`.
