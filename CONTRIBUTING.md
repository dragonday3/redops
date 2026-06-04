# Contributing to redops

Thanks for your interest in contributing. This document covers how to set up the project, submit changes, and the standards we hold contributions to.

## Development Setup

```bash
git clone https://github.com/dragonday3/redops.git
cd redops
python -m venv .venv
source .venv/bin/activate  # Windows: .venv\Scripts\activate
pip install -e ".[dev]"
```

## Running Tests

```bash
# All tests
pytest tests/ -q

# With coverage
pytest --cov=redops --cov-report=term-missing tests/

# Specific module
pytest tests/test_opsec.py -v
```

All PRs must keep the test suite green across Python 3.10, 3.11, and 3.12.

## Adding a New OPSEC Check

1. Add an async `check_your_check(domain: str) -> OpsecCheckResult` function in `src/redops/opsec/checks.py`
2. Return `status="skip"` on any exception — never raise
3. Register it in `OpsecEngine.run()` inside `src/redops/opsec/engine.py`
4. Add ≥3 tests in `tests/test_opsec.py` (pass, fail, skip — all mocked)
5. Document it in `README.md` under the OPSEC Checks table

## Important Constraints

- **No offensive tooling.** redops is a management layer only — no C2, implants, payload delivery, or exploit code.
- **OPSEC checks target your own infra only.** Never add checks that probe or enumerate third-party targets.
- All network/I/O calls in tests must be mocked.

## Submitting Changes

1. Fork the repo and create a feature branch: `git checkout -b feat/your-feature`
2. Write tests first (TDD preferred)
3. Keep commits atomic — one logical change per commit
4. Run the full test suite before opening a PR
5. Open a PR against `main` with a clear description of what and why

## PR Requirements

- [ ] Tests pass (`pytest tests/ -q`)
- [ ] New code has test coverage
- [ ] No offensive capabilities introduced
- [ ] README updated if behavior changes
- [ ] Commit messages are clear and descriptive

## Reporting Bugs

Open a GitHub issue with:
- Python version and OS
- Minimal reproduction steps
- Expected vs actual behavior
- Full error traceback if applicable

## Security Issues

Do **not** open a public issue for security vulnerabilities. See [SECURITY.md](SECURITY.md).
