from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timezone

db = SQLAlchemy()


class User(UserMixin, db.Model):
    __tablename__ = 'users'

    id            = db.Column(db.Integer, primary_key=True)
    username      = db.Column(db.String(80),  unique=True, nullable=False)
    email         = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(256), nullable=False)
    full_name     = db.Column(db.String(120))
    department    = db.Column(db.String(100))
    role          = db.Column(db.String(20),  default='staff')   # 'admin' | 'staff'
    is_active     = db.Column(db.Boolean,     default=True)
    last_login    = db.Column(db.DateTime(timezone=True))
    created_at    = db.Column(db.DateTime(timezone=True),
                              default=lambda: datetime.now(timezone.utc))

    documents  = db.relationship('Document',     backref='owner',    lazy=True)
    activity   = db.relationship('ActivityLog',  backref='user',     lazy=True)
    devices    = db.relationship('Device',       backref='user',     lazy=True)
    alerts     = db.relationship('SecurityAlert',backref='user',     lazy=True)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    def __repr__(self):
        return f'<User {self.username}>'


class Document(db.Model):
    __tablename__ = 'documents'

    id                 = db.Column(db.Integer,  primary_key=True)
    original_filename  = db.Column(db.String(255), nullable=False)
    encrypted_filename = db.Column(db.String(255), nullable=False, unique=True)
    file_size          = db.Column(db.Integer,  default=0)       # bytes
    file_type          = db.Column(db.String(20))                # pdf|docx|xlsx|pptx
    category           = db.Column(db.String(100), default='General')
    description        = db.Column(db.Text)
    access_level       = db.Column(db.String(20),  default='staff')  # public|staff|admin
    department         = db.Column(db.String(100))
    user_id            = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    upload_date        = db.Column(db.DateTime(timezone=True),
                                   default=lambda: datetime.now(timezone.utc))
    view_count         = db.Column(db.Integer, default=0)
    download_count     = db.Column(db.Integer, default=0)
    is_deleted         = db.Column(db.Boolean, default=False)

    def __repr__(self):
        return f'<Document {self.original_filename}>'


class ActivityLog(db.Model):
    __tablename__ = 'activity_logs'

    id          = db.Column(db.Integer,  primary_key=True)
    user_id     = db.Column(db.Integer,  db.ForeignKey('users.id'), nullable=True)
    action      = db.Column(db.String(50),  nullable=False)
    description = db.Column(db.Text)
    ip_address  = db.Column(db.String(50))
    device_info = db.Column(db.String(500))
    document_id = db.Column(db.Integer,  db.ForeignKey('documents.id'), nullable=True)
    status      = db.Column(db.String(20), default='success')
    timestamp   = db.Column(db.DateTime(timezone=True),
                            default=lambda: datetime.now(timezone.utc))

    def __repr__(self):
        return f'<ActivityLog {self.action}>'


class Device(db.Model):
    __tablename__ = 'devices'

    id                  = db.Column(db.Integer, primary_key=True)
    user_id             = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    device_fingerprint  = db.Column(db.String(256), nullable=False)
    device_name         = db.Column(db.String(100))
    browser             = db.Column(db.String(100))
    os                  = db.Column(db.String(100))
    ip_address          = db.Column(db.String(50))
    is_trusted          = db.Column(db.Boolean, default=False)
    last_seen           = db.Column(db.DateTime(timezone=True))
    registered_at       = db.Column(db.DateTime(timezone=True),
                                    default=lambda: datetime.now(timezone.utc))

    def __repr__(self):
        return f'<Device {self.device_name} user={self.user_id}>'


class SecurityAlert(db.Model):
    __tablename__ = 'security_alerts'

    id          = db.Column(db.Integer,  primary_key=True)
    alert_type  = db.Column(db.String(50),  nullable=False)
    description = db.Column(db.Text)
    ip_address  = db.Column(db.String(50))
    user_id     = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=True)
    severity    = db.Column(db.String(20), default='medium')  # low|medium|high|critical
    is_resolved = db.Column(db.Boolean, default=False)
    timestamp   = db.Column(db.DateTime(timezone=True),
                            default=lambda: datetime.now(timezone.utc))

    def __repr__(self):
        return f'<SecurityAlert {self.alert_type}>'
