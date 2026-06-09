# Secure Document Vault 

A production-grade Flask application for encrypted document storage with a premium Dark Cyberpunk Glassmorphism UI.

## Features
- **AES-256 Fernet encryption** on all uploaded files
- **Device fingerprinting** with admin approval workflow
- **Role-based access control** (admin / staff)
- **Session timeout** with live countdown widget
- **Audit logging** for all actions
- **Security alert system** with severity levels
- **Premium UI** — glassmorphic dark cyberpunk aesthetic
- **Toast notifications** replacing raw flash messages
- **Instant table filtering** (client-side, no reload)
- **Password strength meter** on all auth forms
- **Drag-and-drop file upload** with preview

## Quick Start

### 1. Install dependencies
```bash
pip install -r requirements.txt
```

### 2. Run the application
```bash
python run.py
```
The app will be available at `http://localhost:5000`

### 3. Default admin credentials
```
Username: admin
Password: Admin@1234
```
**Change these immediately after first login.**

## Project Structure
```
SecureDocumentVault/
├── app.py                  # Flask application & all routes (DO NOT MODIFY)
├── models.py               # SQLAlchemy database models
├── config.py               # Configuration (sessions, paths, CSRF)
├── run.py                  # Entry point
├── requirements.txt        # Python dependencies
├── instance/               # SQLite database (auto-created)
├── encrypted_storage/      # Encrypted .enc files
├── keys/                   # Fernet master key (keep secret!)
├── logs/                   # Application logs
├── static/
│   └── css/
│       └── style.css       # Complete design system
└── templates/
    ├── base.html           # Master layout with sidebar & session timer
    ├── login.html          # Standalone cinematic login
    ├── register.html       # User registration
    ├── dashboard.html      # Analytics dashboard
    ├── documents.html      # Document vault with live filter
    ├── upload.html         # Drag-and-drop secure upload
    ├── profile.html        # User profile & password change
    ├── admin_users.html    # User management
    ├── admin_devices.html  # Device registry & approval
    ├── admin_logs.html     # Paginated audit logs
    ├── admin_alerts.html   # Security alert management
    └── error.html          # 403/404/500 error pages
```

## Security Notes
- The `keys/master.key` file is critical. Back it up securely and never commit it to version control.
- Session timeout is set to 5 minutes by default (configurable in `config.py`).
- All file uploads are validated against the allowed extensions whitelist.
- CSRF protection is enabled on all POST forms via Flask-WTF.

Live: https://securefilevault-1qxs.onrender.com/
