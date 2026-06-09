import os
import secrets
from datetime import timedelta

BASE_DIR = os.path.abspath(os.path.dirname(__file__))

class Config:
    # Flask
    SECRET_KEY = os.environ.get('SECRET_KEY') or secrets.token_hex(32)

    # Database — on Render, write to /tmp so the path is always writable.
    # For local dev, instance/ inside the project folder is used.
    _db_dir = os.environ.get('DB_DIR') or os.path.join(BASE_DIR, 'instance')
    os.makedirs(_db_dir, exist_ok=True)          # ensure folder exists
    SQLALCHEMY_DATABASE_URI = (
        os.environ.get('DATABASE_URL') or
        'sqlite:///' + os.path.join(_db_dir, 'database.db')
    )
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    # Session Settings
    PERMANENT_SESSION_LIFETIME = timedelta(minutes=5)
    SESSION_PERMANENT = False
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = 'Lax'
    SESSION_COOKIE_SECURE = os.environ.get('SESSION_COOKIE_SECURE', 'False') == 'True'

    # Folder Settings
    UPLOAD_FOLDER      = os.path.join(BASE_DIR, 'uploads')
    ENCRYPTED_FOLDER   = os.path.join(BASE_DIR, 'encrypted_storage')
    KEYS_FOLDER        = os.path.join(BASE_DIR, 'keys')
    LOGS_FOLDER        = os.path.join(BASE_DIR, 'logs')

    MAX_CONTENT_LENGTH = 50 * 1024 * 1024   # 50 MB
    ALLOWED_EXTENSIONS = {'pdf', 'docx', 'xlsx', 'pptx'}

    # CSRF
    WTF_CSRF_ENABLED    = True
    WTF_CSRF_TIME_LIMIT = 3600

    SESSION_TIMEOUT = 300
