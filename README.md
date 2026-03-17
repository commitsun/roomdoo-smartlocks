# roomdoo-smartlocks

Monorepo for Roomdoo smart lock integration libraries. Each subdirectory contains an independent Python package that can be installed and versioned separately.

## Packages

| Package | Description |
|---|---|
| [roomdoo-locks-base](roomdoo-locks-base/) | Abstract contract (interface, exceptions, return types) that all vendor libraries must implement |

Vendor-specific implementations (e.g. TTLock, Nuki, Yale) will live as sibling directories following the same convention.

## Architecture

```
roomdoo-smartlocks/
├── roomdoo-locks-base/      # Abstract interface — no vendor dependencies
├── roomdoo-locks-ttlock/    # (future) TTLock implementation
├── roomdoo-locks-nuki/      # (future) Nuki implementation
└── ...
```

The PMS (Roomdoo) depends only on `roomdoo-locks-base` at the interface level. Vendor packages are injected at runtime, keeping the PMS decoupled from any specific lock vendor.

## Development

### Prerequisites

- Python >= 3.10
- [pre-commit](https://pre-commit.com/)

### Setup

```bash
# Install a package in editable mode with dev dependencies
pip install -e "roomdoo-locks-base[dev]"

# Install pre-commit hooks
pre-commit install
```

### Pre-commit hooks

This repo uses [pre-commit](https://pre-commit.com/) with the following hooks:

- **ruff** — linting and formatting (replaces flake8, isort, black)
- **mypy** — static type checking
- **General checks** — trailing whitespace, EOF fixer, YAML/TOML validation, merge conflict detection, large file guard

Run all hooks manually against all files:

```bash
pre-commit run --all-files
```

## License

Proprietary — Roomdoo.
