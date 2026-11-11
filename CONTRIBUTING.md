# Contributing

Thanks for considering a contribution to SentinelSOC.

## Development setup

Use Python 3.10 or newer. From the repository root, create and activate a virtual environment, then install the project requirements:

```powershell
python -m venv venv
venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
```

## Before opening a pull request

- Run `python -m pytest -q --basetemp=.pytest-tmp`.
- Keep changes focused and explain behavior changes in the README when relevant.
- Add tests for parser, detection, persistence, or route behavior you change.
- Do not commit local databases, uploaded logs containing real data, secrets, virtual environments, or generated caches.
- Describe the change, verification performed, and any limitations in the pull request.

## Scope

SentinelSOC is a local rule-based monitoring demonstration. Contributions should preserve safe parameterized database access, input validation, CSRF checks on state-changing routes, and clear language that alerts indicate suspicious activity rather than confirmed compromise.
