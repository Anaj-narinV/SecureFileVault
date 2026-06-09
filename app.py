import os
import uuid
import hashlib
import json
import logging
import mimetypes
import tempfile
import shutil
from datetime import datetime, timedelta, timezone
from functools import wraps
from flask import (Flask, render_template, redirect, url_for, flash, request,
                   session, send_file, jsonify, abort, make_response)
from flask_login import LoginManager, login_user, logout_user, login_required, current_user
from flask_wtf.csrf import CSRFProtect
from werkzeug.utils import secure_filename
from cryptography.fernet import Fernet
from models import db, User, Document, ActivityLog, Device, SecurityAlert
from config import Config

BASE_DIR = os.path.abspath(os.path.dirname(__file__))

# ── App setup ──────────────────────────────────────────────────────────────
app = Flask(__name__)
app.config.from_object(Config)

db.init_app(app)
csrf = CSRFProtect(app)

login_manager = LoginManager(app)
login_manager.login_view = 'login'
login_manager.login_message = 'Please log in to access this page.'
login_manager.login_message_category = 'warning'

# Ensure directories exist
os.makedirs(app.config.get('UPLOAD_FOLDER', os.path.join(BASE_DIR, "uploads")), exist_ok=True)
os.makedirs(app.config.get('ENCRYPTED_FOLDER', os.path.join(BASE_DIR, "encrypted")), exist_ok=True)
os.makedirs(app.config.get('KEYS_FOLDER', os.path.join(BASE_DIR, "keys")), exist_ok=True)
os.makedirs(app.config.get('LOGS_FOLDER', os.path.join(BASE_DIR, "logs")), exist_ok=True)

# File logger
logging.basicConfig(
    filename=os.path.join(app.config.get('LOGS_FOLDER', os.path.join(BASE_DIR, "logs")), 'app.log'),
    level=logging.INFO,
    format='%(asctime)s %(levelname)s %(message)s'
)

# ── Encryption helpers ──────────────────────────────────────────────────────
KEY_FILE = os.path.join(app.config.get('KEYS_FOLDER', os.path.join(BASE_DIR, "keys")), 'master.key')

def get_fernet():
    if not os.path.exists(KEY_FILE):
        key = Fernet.generate_key()
        with open(KEY_FILE, 'wb') as f:
            f.write(key)
    with open(KEY_FILE, 'rb') as f:
        return Fernet(f.read())

def encrypt_file(data: bytes) -> bytes:
    return get_fernet().encrypt(data)

def decrypt_file(data: bytes) -> bytes:
    return get_fernet().decrypt(data)

# ── Utility helpers ─────────────────────────────────────────────────────────
def allowed_file(filename):
    return ('.' in filename and
            filename.rsplit('.', 1)[1].lower() in app.config.get('ALLOWED_EXTENSIONS', []))

def log_activity(action, description='', status='success', document_id=None):
    uid = current_user.id if current_user.is_authenticated else None
    entry = ActivityLog(
        user_id=uid,
        action=action,
        description=description,
        ip_address=request.remote_addr,
        device_info=request.user_agent.string[:500],
        document_id=document_id,
        status=status
    )
    db.session.add(entry)
    db.session.commit()
    logging.info(f"[{action}] uid={uid} ip={request.remote_addr} status={status} {description}")

def create_alert(alert_type, description, severity='medium'):
    uid = current_user.id if current_user.is_authenticated else None
    alert = SecurityAlert(
        alert_type=alert_type,
        description=description,
        ip_address=request.remote_addr,
        user_id=uid,
        severity=severity
    )
    db.session.add(alert)
    db.session.commit()

def get_device_fingerprint():
    ua = request.user_agent.string
    ip = request.remote_addr
    raw = f"{ua}|{ip}"
    return hashlib.sha256(raw.encode()).hexdigest()

def admin_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not current_user.is_authenticated or current_user.role != 'admin':
            abort(403)
        return f(*args, **kwargs)
    return decorated

# ── Login manager ──────────────────────────────────────────────────────────
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# ── Session timeout middleware ─────────────────────────────────────────────
@app.before_request
def check_session_timeout():
    exempt = ['login', 'static', 'logout', 'register']
    if request.endpoint in exempt or not request.endpoint:
        return
    if current_user.is_authenticated:
        last = session.get('last_activity')
        if last:
            try:
                last_time = datetime.fromisoformat(last)
                if last_time.tzinfo is None:
                    last_time = last_time.replace(tzinfo=timezone.utc)
                
                elapsed = (datetime.now(timezone.utc) - last_time).total_seconds()
                if elapsed > app.config.get('SESSION_TIMEOUT', 1800):
                    logout_user()
                    session.clear()
                    flash('Session expired due to inactivity.', 'warning')
                    return redirect(url_for('login'))
            except ValueError:
                pass
        session['last_activity'] = datetime.now(timezone.utc).isoformat()

# ── Routes ─────────────────────────────────────────────────────────────────

@app.route('/')
def index():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))

# ── Auth ───────────────────────────────────────────────────────────────────
@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        user = User.query.filter_by(username=username).first()
        if not user or not user.check_password(password):
            log_activity('LOGIN_FAILED', f'Failed login for: {username}', 'failed')
            create_alert('FAILED_LOGIN', f'Failed login attempt for username: {username}', 'medium')
            flash('Invalid username or password.', 'danger')
            return render_template('login.html')
        if not user.is_active:
            flash('Account is disabled. Contact admin.', 'danger')
            return render_template('login.html')

        # Device check
        fp = get_device_fingerprint()
        device = Device.query.filter_by(user_id=user.id, device_fingerprint=fp).first()
        if not device:
            ua = request.user_agent
            # Admin devices are always auto-trusted so the first login is never blocked
            auto_trust = (user.role == 'admin')
            new_dev = Device(
                user_id=user.id,
                device_fingerprint=fp,
                device_name=ua.platform or 'Unknown',
                browser=ua.browser or 'Unknown',
                os=ua.platform or 'Unknown',
                ip_address=request.remote_addr,
                is_trusted=auto_trust
            )
            db.session.add(new_dev)
            db.session.commit()
            if auto_trust:
                device = new_dev
            else:
                log_activity('DEVICE_PENDING', f'New device pending approval for {username}', 'warning')
                create_alert('NEW_DEVICE', f'Unrecognized device login attempt by {username}', 'high')
                flash('New device detected. Awaiting admin approval.', 'warning')
                return render_template('login.html')

        if not device.is_trusted:
            flash('Device access pending administrative verification.', 'warning')
            return render_template('login.html')

        # Success
        device.last_seen = datetime.now(timezone.utc)
        user.last_login = datetime.now(timezone.utc)
        db.session.commit()
        login_user(user)
        session['last_activity'] = datetime.now(timezone.utc).isoformat()
        session.permanent = False
        log_activity('LOGIN', f'User {username} logged in successfully')
        flash(f'Welcome back, {user.full_name or username}!', 'success')
        return redirect(url_for('dashboard'))
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    log_activity('LOGOUT', f'User {current_user.username} logged out')
    logout_user()
    session.clear()
    flash('You have been logged out.', 'info')
    return redirect(url_for('login'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        email = request.form.get('email', '').strip()
        password = request.form.get('password', '')
        confirm = request.form.get('confirm_password', '')
        full_name = request.form.get('full_name', '').strip()
        department = request.form.get('department', '').strip()

        if password != confirm:
            flash('Passwords do not match.', 'danger')
            return render_template('register.html')
        if len(password) < 8:
            flash('Password must be at least 8 characters.', 'danger')
            return render_template('register.html')
        if User.query.filter_by(username=username).first():
            flash('Username already taken.', 'danger')
            return render_template('register.html')
        if User.query.filter_by(email=email).first():
            flash('Email already registered.', 'danger')
            return render_template('register.html')

        user = User(username=username, email=email, full_name=full_name, department=department)
        user.set_password(password)
        user.role = 'staff'
        db.session.add(user)
        db.session.commit()

        fp = get_device_fingerprint()
        ua = request.user_agent
        dev = Device(
            user_id=user.id,
            device_fingerprint=fp,
            device_name=ua.platform or 'Unknown',
            browser=ua.browser or 'Unknown',
            os=ua.platform or 'Unknown',
            ip_address=request.remote_addr,
            is_trusted=True
        )
        db.session.add(dev)
        db.session.commit()
        flash('Registration successful! You can now log in.', 'success')
        return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/dashboard')
@login_required
def dashboard():
    total_docs = Document.query.filter_by(is_deleted=False).count()
    total_users = User.query.count()

    total_downloads = db.session.query(db.func.sum(Document.download_count)).scalar() or 0

    pdf_count = Document.query.filter_by(file_type='pdf', is_deleted=False).count()
    docx_count = Document.query.filter_by(file_type='docx', is_deleted=False).count()
    pptx_count = Document.query.filter_by(file_type='pptx', is_deleted=False).count()
    xlsx_count = Document.query.filter_by(file_type='xlsx', is_deleted=False).count()

    recent_uploads = (
        Document.query
        .filter_by(is_deleted=False)
        .order_by(Document.upload_date.desc())
        .limit(5)
        .all()
    )

    if current_user.role == 'admin':
        recent_logs = (
            ActivityLog.query
            .order_by(ActivityLog.timestamp.desc())
            .limit(10)
            .all()
        )
    else:
        recent_logs = []

    alerts = (
        SecurityAlert.query
        .filter_by(is_resolved=False)
        .order_by(SecurityAlert.timestamp.desc())
        .limit(5)
        .all()
    )

    recent_users = (
        User.query
        .order_by(User.created_at.desc())
        .limit(5)
        .all()
    )

    chart_labels = []
    chart_data = []

    for i in range(6, -1, -1):
        day = datetime.now(timezone.utc).date() - timedelta(days=i)
        count = Document.query.filter(
            db.func.date(Document.upload_date) == day,
            Document.is_deleted == False
        ).count()
        chart_labels.append(day.strftime('%b %d'))
        chart_data.append(count)

    return render_template(
        'dashboard.html',
        total_docs=total_docs,
        total_users=total_users,
        total_downloads=total_downloads,
        pdf_count=pdf_count,
        docx_count=docx_count,
        pptx_count=pptx_count,
        xlsx_count=xlsx_count,
        recent_users=recent_users,
        recent_uploads=recent_uploads,
        recent_logs=recent_logs,
        alerts=alerts,
        chart_labels=json.dumps(chart_labels),
        chart_data=json.dumps(chart_data)
    )

# ── Documents ──────────────────────────────────────────────────────────────
@app.route('/documents')
@login_required
def documents():
    q = request.args.get('q', '')
    cat = request.args.get('category', '')
    query = Document.query.filter_by(is_deleted=False)
    if q:
        query = query.filter(Document.original_filename.ilike(f'%{q}%'))
    if cat:
        query = query.filter_by(category=cat)
    if current_user.role != 'admin':
        query = query.filter(Document.access_level.in_(['staff', 'public']))
    docs = query.order_by(Document.upload_date.desc()).all()
    categories = db.session.query(Document.category).distinct().all()
    categories = [c[0] for c in categories if c[0]]
    return render_template('documents.html', docs=docs, categories=categories, q=q, selected_cat=cat)

@app.route('/upload', methods=['GET', 'POST'])
@login_required
def upload():
    if request.method == 'POST':
        try:
            # 1. Verification sequence for tracking structural dictionary payload key
            if 'file' not in request.files:
                flash("Error: Missing multi-part payload file reference constraint.", "danger")
                return redirect(request.url)
                
            file = request.files.get('file')
            if not file or file.filename == '':
                flash("Error: Target element input name metadata parameter empty.", "danger")
                return redirect(request.url)

            # 2. Match standard security constraints rules defined inside configuration files
            if not allowed_file(file.filename):
                flash(f"Error: Selected file schema structure is strictly blacklisted by internal operational rules.", "danger")
                return redirect(request.url)

            # 3. Clean operational target identifiers and split format tokens cleanly
            orig_filename = secure_filename(file.filename)
            file_ext = orig_filename.rsplit('.', 1)[1].lower() if '.' in orig_filename else ''
            
            # Form unique identity tracking key string mapping blocks
            unique_id = str(uuid.uuid4())
            enc_filename = f"{unique_id}.enc"
            
            # 4. Read pure binary streams sequence array elements
            file_bytes = file.read()
            file_size_bytes = len(file_bytes) # Compute absolute size parameters inside runtime memory
            
            # Encrypt block payloads
            encrypted_bytes = encrypt_file(file_bytes)
            
            # Safe checking sequence fallback paths variables
            target_storage_dir = app.config.get('ENCRYPTED_FOLDER', os.path.join(BASE_DIR, 'encrypted_storage'))
            os.makedirs(target_storage_dir, exist_ok=True)
            
            # Commit payload metrics onto static path storage location blocks
            enc_path = os.path.join(target_storage_dir, enc_filename)
            with open(enc_path, 'wb') as f:
                f.write(encrypted_bytes)

            # 5. Extract form data parameters safely matching option tokens cleanly
            category = request.form.get('category', 'General').strip() or 'General'
            access_level = request.form.get('access_level', 'staff').strip() or 'staff'
            description = request.form.get('description', '').strip()

            # 6. Build synchronized model instances mapping every required field attribute precisely
            new_doc = Document(
                original_filename=orig_filename,
                encrypted_filename=enc_filename,
                file_size=file_size_bytes,
                file_type=file_ext,
                category=category,
                description=description if description else None,
                user_id=current_user.id,
                department=current_user.department if hasattr(current_user, 'department') else None, # Checked safety layer
                access_level=access_level
            )

            db.session.add(new_doc)
            db.session.commit()

            # Commit logs structure onto relational system data layers
            log_activity('UPLOAD', f'Asset parsing and encryption mapping executed: {orig_filename}', 'success', new_doc.id)
            flash("Secure target upload workflow completed cleanly!", "success")
            return redirect(url_for('documents'))

        except Exception as e:
            # Active tracking rollback triggers for preventing deadlocks across standard operations
            db.session.rollback()
            logging.error(f"Execution dynamic error encountered inside target system tracking layers: {str(e)}")
            flash(f"Data Pipeline Crash Dump Trace: {str(e)}", "danger")
            return redirect(request.url)

    return render_template('upload.html')

@app.route('/view/<int:doc_id>')
@login_required
def view_document(doc_id):
    doc = Document.query.get_or_404(doc_id)
    if doc.is_deleted:
        abort(404)
    if current_user.role != 'admin' and doc.access_level == 'admin':
        abort(403)

    enc_path = os.path.join(app.config['ENCRYPTED_FOLDER'], doc.encrypted_filename)
    if not os.path.exists(enc_path):
        flash('Encrypted file configuration missing.', 'danger')
        return redirect(url_for('documents'))

    with open(enc_path, 'rb') as f:
        encrypted_data = f.read()
    decrypted_data = decrypt_file(encrypted_data)

    tmp_dir = tempfile.mkdtemp()
    tmp_path = os.path.join(tmp_dir, doc.original_filename)
    with open(tmp_path, 'wb') as f:
        f.write(decrypted_data)

    doc.view_count += 1
    db.session.commit()
    log_activity('VIEW', f'Viewed asset payload: {doc.original_filename}', 'success', doc.id)

    mime = mimetypes.guess_type(doc.original_filename)[0] or 'application/octet-stream'
    response = make_response(send_file(tmp_path, mimetype=mime, as_attachment=False))

    @response.call_on_close
    def cleanup():
        shutil.rmtree(tmp_dir, ignore_errors=True)

    return response

@app.route('/download/<int:doc_id>')
@login_required
def download_document(doc_id):
    doc = Document.query.get_or_404(doc_id)
    if doc.is_deleted:
        abort(404)
    if current_user.role != 'admin' and doc.access_level == 'admin':
        abort(403)

    enc_path = os.path.join(app.config['ENCRYPTED_FOLDER'], doc.encrypted_filename)
    if not os.path.exists(enc_path):
        flash('File tracking mismatch.', 'danger')
        return redirect(url_for('documents'))

    # Path traversal protection validation check
    real_path = os.path.realpath(enc_path)
    if not real_path.startswith(os.path.realpath(app.config['ENCRYPTED_FOLDER'])):
        abort(403)

    with open(enc_path, 'rb') as f:
        encrypted_data = f.read()
    decrypted_data = decrypt_file(encrypted_data)

    doc.download_count += 1
    db.session.commit()
    log_activity('DOWNLOAD', f'Downloaded: {doc.original_filename}', 'success', doc.id)

    tmp_dir = tempfile.mkdtemp()
    tmp_path = os.path.join(tmp_dir, doc.original_filename)
    with open(tmp_path, 'wb') as f:
        f.write(decrypted_data)

    response = make_response(send_file(tmp_path, as_attachment=True, download_name=doc.original_filename))

    @response.call_on_close
    def cleanup():
        shutil.rmtree(tmp_dir, ignore_errors=True)

    return response

@app.route('/delete/<int:doc_id>', methods=['POST'])
@login_required
def delete_document(doc_id):
    doc = Document.query.get_or_404(doc_id)
    if current_user.role != 'admin' and doc.user_id != current_user.id:
        abort(403)
    doc.is_deleted = True
    db.session.commit()
    log_activity('DELETE', f'Deleted tracking flag for: {doc.original_filename}', 'success', doc.id)
    flash(f'"{doc.original_filename}" target deleted.', 'success')
    return redirect(url_for('documents'))

# ── Admin ──────────────────────────────────────────────────────────────────
@app.route('/admin/users')
@login_required
@admin_required
def admin_users():
    users = User.query.all()
    user_uploads = {user.id: Document.query.filter_by(user_id=user.id, is_deleted=False).count() for user in users}
    return render_template('admin_users.html', users=users, user_uploads=user_uploads)

@app.route('/admin/users/toggle/<int:user_id>', methods=['POST'])
@login_required
@admin_required
def toggle_user(user_id):
    user = User.query.get_or_404(user_id)
    if user.id == current_user.id:
        flash("Cannot deactivate yourself.", "warning")
        return redirect(url_for('admin_users'))
    user.is_active = not user.is_active
    db.session.commit()
    status = 'activated' if user.is_active else 'deactivated'
    flash(f'User {user.username} state changed to {status}.', 'success')
    return redirect(url_for('admin_users'))

@app.route('/admin/users/role/<int:user_id>', methods=['POST'])
@login_required
@admin_required
def change_role(user_id):
    user = User.query.get_or_404(user_id)
    new_role = request.form.get('role')
    if new_role in ['admin', 'staff']:
        user.role = new_role
        db.session.commit()
        flash(f'Role updated to {new_role}.', 'success')
    return redirect(url_for('admin_users'))

@app.route('/admin/devices')
@login_required
@admin_required
def admin_devices():
    devices = Device.query.order_by(Device.registered_at.desc()).all()
    return render_template('admin_devices.html', devices=devices)

@app.route('/admin/devices/approve/<int:device_id>', methods=['POST'])
@login_required
@admin_required
def approve_device(device_id):
    device = Device.query.get_or_404(device_id)
    device.is_trusted = True
    db.session.commit()
    log_activity('DEVICE_APPROVED', f'Device approved for user_id={device.user_id}')
    flash('Device access allowed.', 'success')
    return redirect(url_for('admin_devices'))

@app.route('/admin/devices/revoke/<int:device_id>', methods=['POST'])
@login_required
@admin_required
def revoke_device(device_id):
    device = Device.query.get_or_404(device_id)
    device.is_trusted = False
    db.session.commit()
    flash('Device trust standard revoked.', 'warning')
    return redirect(url_for('admin_devices'))

@app.route('/admin/logs')
@login_required
@admin_required
def admin_logs():
    page = request.args.get('page', 1, type=int)
    action_filter = request.args.get('action', '')
    query = ActivityLog.query.order_by(ActivityLog.timestamp.desc())
    if action_filter:
        query = query.filter_by(action=action_filter)
    logs = query.paginate(page=page, per_page=20)
    actions = db.session.query(ActivityLog.action).distinct().all()
    actions = [a[0] for a in actions if a[0]]
    return render_template('admin_logs.html', logs=logs, actions=actions, action_filter=action_filter)

@app.route('/admin/alerts')
@login_required
@admin_required
def admin_alerts():
    alerts = SecurityAlert.query.order_by(SecurityAlert.timestamp.desc()).all()
    return render_template('admin_alerts.html', alerts=alerts)

@app.route('/admin/alerts/resolve/<int:alert_id>', methods=['POST'])
@login_required
@admin_required
def resolve_alert(alert_id):
    alert = SecurityAlert.query.get_or_404(alert_id)
    alert.is_resolved = True
    db.session.commit()
    flash('Alert marked as resolved.', 'success')
    return redirect(url_for('admin_alerts'))

# ── Profile ────────────────────────────────────────────────────────────────
@app.route('/profile', methods=['GET', 'POST'])
@login_required
def profile():
    if request.method == 'POST':
        current_user.full_name = request.form.get('full_name', current_user.full_name)
        current_user.department = request.form.get('department', current_user.department)
        current_user.email = request.form.get('email', current_user.email)
        db.session.commit()
        flash('Profile settings updated successfully.', 'success')
    return render_template('profile.html')

@app.route('/change-password', methods=['POST'])
@login_required
def change_password():
    old_pw = request.form.get('old_password')
    new_pw = request.form.get('new_password')
    confirm = request.form.get('confirm_password')
    if not current_user.check_password(old_pw):
        flash('Current password verification failed.', 'danger')
        return redirect(url_for('profile'))
    if new_pw != confirm:
        flash('New security passwords mismatch.', 'danger')
        return redirect(url_for('profile'))
    if len(new_pw) < 8:
        flash('Security policy complexity metrics failed.', 'danger')
        return redirect(url_for('profile'))
    current_user.set_password(new_pw)
    db.session.commit()
    log_activity('PASSWORD_CHANGE', 'Password altered successfully')
    flash('Password changed properly.', 'success')
    return redirect(url_for('profile'))

# ── API: session ping ──────────────────────────────────────────────────────
@app.route('/api/ping', methods=['POST'])
@login_required
def ping():
    session['last_activity'] = datetime.now(timezone.utc).isoformat()
    return jsonify({'status': 'ok'})

@app.route('/api/session-status')
@login_required
def session_status():
    last = session.get('last_activity')
    if last:
        try:
            last_time = datetime.fromisoformat(last)
            if last_time.tzinfo is None:
                last_time = last_time.replace(tzinfo=timezone.utc)
            elapsed = (datetime.now(timezone.utc) - last_time).total_seconds()
            remaining = max(0, app.config.get('SESSION_TIMEOUT', 1800) - elapsed)
        except ValueError:
            remaining = app.config.get('SESSION_TIMEOUT', 1800)
    else:
        remaining = app.config.get('SESSION_TIMEOUT', 1800)
    return jsonify({'remaining': int(remaining)})

# ── Error handlers ─────────────────────────────────────────────────────────
@app.errorhandler(403)
def forbidden(e):
    return render_template('error.html', code=403, message='Access Forbidden'), 403

@app.errorhandler(404)
def not_found(e):
    return render_template('error.html', code=404, message='Page Not Found'), 404

@app.errorhandler(500)
def server_error(e):
    return render_template('error.html', code=500, message='Internal Server Error'), 500

# ── DB init & seed ─────────────────────────────────────────────────────────
def init_db():
    with app.app_context():
        db.create_all()
        if User.query.count() == 0:
            admin = User(
                username='admin',
                email='admin@rimt.edu.in',
                full_name='System Administrator',
                department='IT',
                role='admin',
                is_active=True
            )
            admin.set_password('Admin@1234')
            db.session.add(admin)
            db.session.flush()  # get admin.id before commit

            # Seed trusted device so admin is never locked out on first boot.
            # The login route also auto-trusts any device belonging to an admin.
            seed_device = Device(
                user_id=admin.id,
                device_fingerprint='seed-admin-trusted',
                device_name='Seeded Admin Device',
                browser='Any',
                os='Any',
                ip_address='127.0.0.1',
                is_trusted=True
            )
            db.session.add(seed_device)
            db.session.commit()
            print("Default admin created — username: admin  password: Admin@1234")
        print("Database initialised successfully.")

if __name__ == '__main__':
    init_db()
    app.run(debug=True, host='0.0.0.0', port=5000)