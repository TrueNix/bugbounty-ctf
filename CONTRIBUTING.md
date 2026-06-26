# Contributing

Thanks for your interest in improving `bugbounty-ctf`!

## Development Setup

```bash
git clone https://github.com/TrueNix/bugbounty-ctf.git
cd bugbounty-ctf
pip install -e ".[dev]"
```

## Before Submitting a PR

1. **Lint passes:** `ruff check src/ tests/`
2. **Type check passes:** `mypy src/bugbounty_ctf/`
3. **Tests pass:** `pytest --cov=bugbounty_ctf`
4. **Coverage ≥ 80%:** maintained for new code

## Code Style

- Python 3.10+ (use modern syntax: `X | None`, `match` statements where appropriate)
- Type hints on all public functions
- `ruff` for linting and formatting (enforced in CI)
- No `as any`, `# type: ignore`, or bare `except:`
- Functions that make HTTP requests should accept an optional `scanner` parameter
  to allow state reuse across tests

## Adding a New Test Function

1. Add the function to the appropriate module (`quick_tests.py` or `advanced_tests.py`)
2. Export it from `api.py` and add to `__all__`
3. Add tests in `tests/` with mocked HTTP via `responses` library
4. Document it in `README.md` features table

## Reporting Issues

- Bug reports: include Python version, OS, and a minimal reproduction
- Feature requests: describe the use case, not just the implementation
- Security issues: see [SECURITY.md](SECURITY.md) — do not open a public issue