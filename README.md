# Murang'a County PSB — Public Service Request System

An educational Flask prototype for a mini eCitizen-style public service request portal. Citizens can report issues such as broken streetlights, water supply problems, garbage collection, roads and drainage, and other public service concerns.

## Features
- Citizen registration and sign-in (passwords are hashed)
- Submit requests by category, location, title, and description
- Optional image attachment (PNG, JPG, JPEG, GIF, WEBP; up to 5 MB)
- Unique request reference numbers
- Citizen dashboard and request tracking
- Administrator dashboard, open/resolved analytics, status updates, and notes
- SQLite database for a simple demo deployment

## Run locally
1. Install Python 3.11 or newer.
2. Create and activate a virtual environment.
3. Install dependencies:
   `pip install -r requirements.txt`
4. Start the app:
   `python app.py`
5. Open `http://127.0.0.1:5000`.

## Configure an administrator
Set these environment variables before the first run:
- `SECRET_KEY`: a long, random secret value
- `ADMIN_EMAIL`: administrator email
- `ADMIN_PASSWORD`: a strong administrator password

The application creates the administrator account if it does not already exist. For local testing on Windows PowerShell, for example:

```powershell
$env:SECRET_KEY="replace-with-a-long-random-value"
$env:ADMIN_EMAIL="admin@example.com"
$env:ADMIN_PASSWORD="Use-A-Strong-Unique-Password"
python app.py
```

Do not publish real passwords or secret keys in source code or screenshots.

## Deploy
This app can be deployed to a Python hosting service that supports Flask and Gunicorn. Configure `SECRET_KEY`, `ADMIN_EMAIL`, and `ADMIN_PASSWORD` as environment variables in the hosting dashboard, then deploy from GitHub using the `Procfile`.

**Database note:** SQLite is suitable for a classroom/demo prototype. On hosts with ephemeral filesystems, the database may reset when the service restarts or redeploys. For persistent use, configure a managed database and backups.

## Image uploads
Uploaded images are saved in `static/uploads/`. This is suitable for a local demo; for a public deployment, use managed object storage and configure upload scanning and retention rules.

## Important
This is a student project prototype, not an official Murang'a County Government website. It is not integrated with county systems, eCitizen, SMS, email, or identity verification. Do not use it to collect real sensitive personal information. Before any real-world use, add CSRF protection, rate limiting, audit logging, secure account recovery, accessibility testing, privacy notices, and a persistent production database, and obtain authorization to represent the County PSB.
