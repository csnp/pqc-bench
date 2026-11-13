# Contributing

We welcome contributions!

```bash
# Development setup
git clone https://github.com/csnp/pqc-bench.git
cd pqc-bench
pip install -e ".[dev]"
```

## Checks

Run these three checks before you open a pull request. Each one is configured in `pyproject.toml`, and `pip install -e ".[dev]"` installs the tools they need.

```bash
pytest           # the test suite ([tool.pytest.ini_options])
ruff check src/  # lint with the rules in [tool.ruff]
mypy src         # strict type checking ([tool.mypy])
```
