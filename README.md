# SentinelSOC

SentinelSOC is a lightweight local SOC monitoring demonstration. It parses Linux SSH authentication records, stores normalized events in SQLite, detects suspicious patterns with transparent rules, and provides an investigator dashboard and CSV exports. It uses synthetic data for its included demonstration and does not block addresses or establish that any activity is malicious.

## Problem and objectives

Authentication logs contain useful signals but are difficult to inspect manually. SentinelSOC makes common SSH outcomes searchable, groups repeated activity into explainable alerts, and keeps a simple audit trail for investigation. It is a Windows-friendly Python application that accepts Linux `auth.log`-style input; no Linux host is needed.

## Features

- Tolerant parsing for standard syslog timestamps and common `sshd` accepted, failed, invalid-user and PAM authentication failure messages.
- Event and alert persistence in SQLite with unique fingerprints and parameterized SQL.
- Alert investigation, status updates, IP activity details, search, filters and pagination.
- Responsive dark dashboard with Chart.js event, severity and category visualizations.
- Validated `.log` / `.txt` upload (5 MiB limit), CSV exports, and labelled-scenario evaluation metrics.
- Synthetic sample log and deterministic ground-truth data generator.

## Technology and architecture

Python 3, Flask, SQLite, Pandas, regular expressions, HTML/CSS/JavaScript, Chart.js and pytest. `core/` contains parsing, detection and evaluation; `database/` owns schema and persistence; `app.py` provides the application and routes; `templates/` and `static/` implement the dashboard. The application creates database tables automatically on startup.

## Detection rules

All rules are configurable from Settings (for the current server run). Defaults are five failures in five minutes for HIGH SSH brute-force, four distinct usernames for MEDIUM multi-username activity, three invalid usernames for MEDIUM enumeration, and eight failures in a five-minute rolling interval for a MEDIUM burst. Two or more failures followed by success from the same IP within five minutes yields a HIGH suspicious-login alert. Rules use event timestamps and source IP grouping. Alert fingerprints and unique database constraints prevent repeat insertion for the same contributing event window. These are indicators for review, not proof of a successful attack.

## Database design

`events` stores timestamp, host, process, username, source IP, outcome, invalid-user flag, raw line and a unique content fingerprint. `alerts` stores source, optional username, category, severity, description, status and linked event IDs. SQLite creates indexes for event time, event source, and alert time during app startup. Alert states are New, Investigating and Resolved.

## Windows setup

PowerShell (first move to the checked-out project directory):

```powershell
Set-Location "C:\path\to\SentinelSOC"
python -m venv venv
venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
python scripts/generate_sample_data.py
python scripts/run_analysis.py
python app.py
```

Open `http://127.0.0.1:5000`. `run_analysis.py` initializes the database (also automatic on app start), processes the sample data and prints actual insertion/alert counts. For an empty database, remove `data/sentinelsoc.db` before starting; the database is local and ignored by git. Set `SENTINELSOC_SECRET` to a private random value for deployments. Debug mode is disabled.

## Using the application

Use **Upload log** to choose a `.log` or `.txt` file up to 5 MiB. Upload data is decoded as text and never executed or saved under the client filename. Parsed records are deduplicated and stored; suspicious patterns create alerts. Explore Alerts and IP activity to review source history, and change an alert's status from its detail page. Forms use a session CSRF token. Reports provides CSV links for all, failed, successful and alert records; date bounds can be selected on that page. Exports are assembled as Pandas dataframes and downloaded as CSV.

## Evaluation

`data/ground_truth.csv` labels each synthetic scenario as normal or intentionally suspicious. `data/evaluation_predictions.csv` is generated from the actual detector output: a scenario is detected when the output includes an alert for its source IP. The Reports page calculates TP, FP, TN, FN, precision, recall, F1, detection rate and false positive rate from those rows, with safe zero division. Regenerate both files when updating sample scenarios using `python scripts/generate_sample_data.py`. This tiny synthetic set demonstrates the evaluation procedure only; its results are not a real-world performance estimate.

## Limitations and future improvements

- The parser targets common Linux syslog SSH messages; journald JSON, arbitrary locale formats and rotated-file management are out of scope.
- Syslog timestamps omit a year and timezone; the parser uses the current year and local-naive timestamps unless a year is supplied by code. Correlation assumes consistent timestamps.
- Settings apply to future uploads during the current process only. Reprocessing a file with changed rules does not revise previously inserted alerts.
- The dashboard is a single-user local demonstration with no authentication, role management, retention policy, external enrichment or automated firewall response. Do not expose it to an untrusted network.
- Chart.js and the optional font are loaded from public CDNs; the rest of the application runs locally.
- Rules are intentionally simple and need tuning for a specific environment. “Suspicious” does not mean “confirmed malicious.”

## Tests

Run `python -m pytest -q --basetemp=.pytest-tmp` to test parser behavior, detection thresholds, deduplication, persistence, metrics, uploads, routes and CSV download. The workspace-local temporary directory also works in restricted Windows environments.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for the development and pull request workflow. See [SECURITY.md](SECURITY.md) for responsible vulnerability reporting.
