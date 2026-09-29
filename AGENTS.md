# Project Instructions

## Scope

This is a small Flask phishing URL detector. Keep changes focused and preserve the existing function names, route behavior, template data keys, and SQLite schema unless the task explicitly requires an API or data change.

## Project Map

- `app.py`: Flask routes, sessions, authentication, scan persistence, and admin authorization.
- `database.py`: SQLite connection, schema initialization, users, scan history, and dashboard queries.
- `features.py`: Ordered URL feature extraction shared by training and inference.
- `detector.py`: Loads `phishing_model.pkl`, predicts from extracted features, and returns scan result fields.
- `train_model.py`: Trains the Random Forest from `phishing.csv` and rewrites `phishing_model.pkl`.
- `templates/`: Flask/Jinja pages for login, registration, scanning, history, and the admin dashboard.
- `.github/skills/phishing-detector-maintenance/SKILL.md`: Detailed workflow for detector, security, authentication, database, and model changes.

## Development

Run commands from the project root with the active virtual environment:

```powershell
python app.py
```

```powershell
python -m compileall app.py database.py detector.py features.py train_model.py
```

```powershell
python -c "from features import extract_features; print(len(extract_features('https://example.com/login')))"
```

Retraining is explicit and regenerates the model artifact:

```powershell
python train_model.py
```

There is currently no checked-in test suite or README. Use Flask's test client for route changes and small direct Python checks for feature/model changes. Avoid modifying the checked-in SQLite databases or model artifact during validation unless regeneration is part of the requested change.

## Change Rules

- For feature changes, update and verify both training and inference; feature order and length must remain identical.
- For route or template changes, trace the database helper and the template's expected context keys together.
- Preserve authentication guards, admin `403` behavior, password hashing, and user-level history boundaries.
- Treat URLs and other request values as untrusted input; rely on Jinja escaping and parameterized SQL.
- Do not expose session secrets, credentials, or database contents in command output.
- Make the smallest relevant edit, then run the narrowest executable validation before further changes.