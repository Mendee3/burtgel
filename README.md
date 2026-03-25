# burtgel

Internal asset registration web app built as a single-file Python WSGI app with SQLite.

## What it does

- Requires login before access.
- Imports department asset data from `extracted/*.xlsx` on first run when the database is empty.
- Supports a one-shot CSV sync for the merged 2025 register.
- Splits data by department.
- Department users can only see and manage their own department assets.
- Admin users can see every department and manage user access.
- Supports CRUD for assets plus audit logs and admin document registers.

## Run

```bash
python3 app.py
```

Then open `http://127.0.0.1:8000`.

## Optional CSV sync

If you have the merged CSV in `data/INFORMATION ASSET REGISTER MERGED 2025.csv`, run:

```bash
python3 app.py sync-csv
```

This provisions the merged departments, creates department users if missing, and replaces asset rows from the CSV.

## Default users

- `admin / admin123`
- `fra_user / fra123`
- `legal_user / legal123`
- `md_user / md123`
- `stg_user / stg123`

Additional department users are created automatically by the CSV sync when needed.

## Configuration

- `BURTGEL_HOST` default: `0.0.0.0`
- `BURTGEL_PORT` default: `8000`
- `BURTGEL_DB_PATH` default: `data/burtgel.db`
- `BURTGEL_IMPORT_DIR` default: `extracted`
- `BURTGEL_SECRET_KEY` default: `change-me-before-production`

## Git notes

The repository is prepared to exclude local runtime data and imported source files:

- `data/*` is ignored except `data/.gitkeep`
- `extracted/*` is ignored except `extracted/.gitkeep`
- `Asset registration.zip` is ignored
- `__pycache__/` is ignored

Add your own seed/source files locally after cloning.
