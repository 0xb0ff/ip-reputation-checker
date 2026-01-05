# Contributing

Thanks for considering contributing!

## Local setup

```bash
python -m venv .venv
source .venv/bin/activate
pip install -U pip
pip install -e ".[dev]"
```

## Run checks

```bash
ruff check .
black --check .
pytest -q
```

## Pull requests

- Keep PRs focused and small.
- Add/adjust tests when possible.
- Make sure CI is green.
