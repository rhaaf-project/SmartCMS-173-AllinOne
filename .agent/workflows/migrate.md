---
description: Run SQL migrations on local db_ucx database
---

# Run Local Migrations

Run SQL migration files from the migrations folder on local MariaDB db_ucx.

// turbo-all

## Steps

1. Run all pending migrations
```powershell
Get-ChildItem -Path "migrations" -Filter "*.sql" | ForEach-Object { Write-Host "Running $_"; Get-Content $_.FullName | & "C:\wamp64\bin\mysql\mysql8.4.7\bin\mysql.exe" -u root db_ucx }
```

## Notes
- Target database: db_ucx (MariaDB)
- Migration files should be in `migrations/` folder
- Uses mysql8.4.7 client
