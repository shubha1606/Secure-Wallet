import os
import io
import sqlite3
import pyotp
from datetime import datetime, timedelta

from cryptography.fernet import Fernet

from flask import (
    Flask,
    render_template,
    request,
    jsonify,
    session,
    send_file
)

from werkzeug.security import (
    generate_password_hash,
    check_password_hash
)

from werkzeug.utils import secure_filename

app = Flask(__name__)

# =========================
# CONFIG
# =========================

app.secret_key = "SECURE_SUPER_SECRET_VAULT_KEY"
app.permanent_session_lifetime = timedelta(minutes=30)

DATABASE = "securevault.db"
MAX_FILE_SIZE_MB = 5
LOGIN_MAX_ATTEMPTS = 5
LOGIN_LOCKOUT_MINUTES = 15

ALLOWED_EXTENSIONS = {'pdf', 'png', 'jpg', 'jpeg', 'doc', 'docx'}

# Fernet symmetric encryption key — in production store this in env/secrets manager
# Generate once with: Fernet.generate_key()
FERNET_KEY = b'ZmDfcTF7_60GrrY167zsiPd67pEvs0aGOv2oasOM1Pg='
fernet = Fernet(FERNET_KEY)


# =========================
# DATABASE HELPERS
# =========================

def get_db():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def init_db():
    # Always re-apply schema so new columns/tables are created on upgrade
    with open("schema.sql", "r") as f:
        schema = f.read()
    conn = get_db()
    conn.executescript(schema)
    conn.commit()
    conn.close()


init_db()


# =========================
# HELPERS
# =========================

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


def log_activity(user_id, action):
    conn = get_db()
    conn.execute(
        "INSERT INTO activity_logs (user_id, action) VALUES (?, ?)",
        (user_id, action)
    )
    conn.commit()
    conn.close()


def encrypt_data(data: bytes) -> bytes:
    return fernet.encrypt(data)


def decrypt_data(data: bytes) -> bytes:
    return fernet.decrypt(data)


def is_account_locked(email: str) -> bool:
    """Return True if the account has >= LOGIN_MAX_ATTEMPTS failed logins in the lockout window."""
    conn = get_db()
    cutoff = datetime.utcnow() - timedelta(minutes=LOGIN_LOCKOUT_MINUTES)
    count = conn.execute(
        """
        SELECT COUNT(*) as cnt FROM login_attempts
        WHERE email = ? AND success = 0 AND attempted_at >= ?
        """,
        (email, cutoff.strftime('%Y-%m-%d %H:%M:%S'))
    ).fetchone()['cnt']
    conn.close()
    return count >= LOGIN_MAX_ATTEMPTS


def record_login_attempt(email: str, success: bool):
    conn = get_db()
    conn.execute(
        "INSERT INTO login_attempts (email, success) VALUES (?, ?)",
        (email, 1 if success else 0)
    )
    conn.commit()
    conn.close()


def clear_login_attempts(email: str):
    conn = get_db()
    conn.execute("DELETE FROM login_attempts WHERE email = ?", (email,))
    conn.commit()
    conn.close()


# =========================
# HOME
# =========================

@app.route('/')
def index():
    return render_template('index.html')


# =========================
# AUTH ROUTES
# =========================

@app.route('/api/auth/status')
def auth_status():
    if 'user_id' in session:
        return jsonify({
            "authenticated": True,
            "name": session['name'],
            "email": session['email'],
            "otp_pending": session.get('otp_pending', False)
        })
    return jsonify({"authenticated": False})


@app.route('/api/auth/signup', methods=['POST'])
def signup():
    data = request.json
    name = data.get('name', '').strip()
    email = data.get('email', '').strip().lower()
    password = data.get('password')

    if not name or not email or not password:
        return jsonify({"error": "All fields are required"}), 400

    hashed_pw = generate_password_hash(password)
    # Generate a TOTP secret for this user
    otp_secret = pyotp.random_base32()

    conn = get_db()
    try:
        cursor = conn.cursor()
        cursor.execute(
            "INSERT INTO users (name, email, password_hash, otp_secret) VALUES (?, ?, ?, ?)",
            (name, email, hashed_pw, otp_secret)
        )
        conn.commit()
        user_id = cursor.lastrowid

        # After signup, require OTP verification before full access
        session['otp_pending'] = True
        session['otp_user_id'] = user_id
        session['otp_name'] = name
        session['otp_email'] = email
        session['otp_secret'] = otp_secret

        log_activity(user_id, "New account created")

        # Return the OTP URI so the frontend can show a demo code
        totp = pyotp.TOTP(otp_secret)
        demo_code = totp.now()

        return jsonify({
            "message": "Account created. OTP required.",
            "otp_required": True,
            "demo_otp": demo_code   # Only for demo — remove in production
        })

    except sqlite3.IntegrityError:
        return jsonify({"error": "Email already exists"}), 400
    finally:
        conn.close()


@app.route('/api/auth/login', methods=['POST'])
def login():
    data = request.json
    email = data.get('email', '').strip().lower()
    password = data.get('password')

    # Check lockout before querying user
    if is_account_locked(email):
        return jsonify({
            "error": f"Account locked for {LOGIN_LOCKOUT_MINUTES} minutes due to too many failed attempts."
        }), 429

    conn = get_db()
    user = conn.execute(
        "SELECT * FROM users WHERE email = ?", (email,)
    ).fetchone()
    conn.close()

    if user and check_password_hash(user['password_hash'], password):
        clear_login_attempts(email)

        # Store pending OTP state — full session set only after OTP verified
        session['otp_pending'] = True
        session['otp_user_id'] = user['id']
        session['otp_name'] = user['name']
        session['otp_email'] = user['email']
        session['otp_secret'] = user['otp_secret']

        totp = pyotp.TOTP(user['otp_secret'])
        demo_code = totp.now()

        return jsonify({
            "message": "Password verified. OTP required.",
            "otp_required": True,
            "demo_otp": demo_code   # Only for demo — remove in production
        })

    record_login_attempt(email, False)

    # Count remaining attempts
    conn = get_db()
    cutoff = datetime.utcnow() - timedelta(minutes=LOGIN_LOCKOUT_MINUTES)
    fail_count = conn.execute(
        "SELECT COUNT(*) as cnt FROM login_attempts WHERE email = ? AND success = 0 AND attempted_at >= ?",
        (email, cutoff.strftime('%Y-%m-%d %H:%M:%S'))
    ).fetchone()['cnt']
    conn.close()

    remaining = max(0, LOGIN_MAX_ATTEMPTS - fail_count)
    return jsonify({
        "error": f"Invalid email or password. {remaining} attempt(s) remaining."
    }), 401


@app.route('/api/auth/verify-otp', methods=['POST'])
def verify_login_otp():
    """Verify the TOTP code after password check. Completes the login."""
    if not session.get('otp_pending'):
        return jsonify({"error": "No pending OTP session"}), 400

    data = request.json
    otp_code = data.get('otp', '').strip()
    secret = session.get('otp_secret')

    totp = pyotp.TOTP(secret)
    # valid_window=1 allows ±30s clock drift
    if not totp.verify(otp_code, valid_window=1):
        return jsonify({"error": "Invalid or expired OTP code"}), 401

    # OTP verified — promote to full session
    user_id = session.pop('otp_user_id')
    name = session.pop('otp_name')
    email = session.pop('otp_email')
    session.pop('otp_secret', None)
    session.pop('otp_pending', None)

    session.permanent = True
    session['user_id'] = user_id
    session['name'] = name
    session['email'] = email

    log_activity(user_id, "User logged in (2FA verified)")

    return jsonify({"message": "Login successful", "name": name})


@app.route('/api/auth/logout', methods=['POST'])
def logout():
    if 'user_id' in session:
        log_activity(session['user_id'], "User logged out")
    session.clear()
    return jsonify({"message": "Logged out successfully"})


# =========================
# KYC / USER PROFILE
# =========================

@app.route('/api/user/kyc')
def get_kyc():
    if 'user_id' not in session:
        return jsonify({"error": "Unauthorized"}), 401
    conn = get_db()
    user = conn.execute(
        "SELECT kyc_verified, phone_number FROM users WHERE id = ?",
        (session['user_id'],)
    ).fetchone()
    conn.close()
    return jsonify({
        "kycVerified": bool(user['kyc_verified']),
        "phoneNumber": user['phone_number'] or ""
    })


@app.route('/api/user/verify-otp', methods=['POST'])
def verify_kyc_otp():
    if 'user_id' not in session:
        return jsonify({"error": "Unauthorized"}), 401
    data = request.json
    otp = data.get('otp')
    phone = data.get('phone')
    if otp != "1234":
        return jsonify({"error": "Invalid OTP"}), 400
    conn = get_db()
    conn.execute(
        "UPDATE users SET kyc_verified = 1, phone_number = ? WHERE id = ?",
        (phone, session['user_id'])
    )
    conn.commit()
    conn.close()
    log_activity(session['user_id'], "KYC verified")
    return jsonify({"message": "KYC verified successfully"})


# =========================
# DASHBOARD
# =========================

@app.route('/api/dashboard/stats')
def dashboard_stats():
    if 'user_id' not in session:
        return jsonify({"error": "Unauthorized"}), 401

    conn = get_db()
    total_docs = conn.execute(
        "SELECT COUNT(*) as count FROM documents WHERE user_id = ?",
        (session['user_id'],)
    ).fetchone()['count']

    total_size = conn.execute(
        "SELECT SUM(file_size_bytes) as total FROM documents WHERE user_id = ?",
        (session['user_id'],)
    ).fetchone()['total']

    conn.close()
    return jsonify({
        "totalDocuments": total_docs,
        "totalStorageBytes": total_size or 0
    })


@app.route('/api/dashboard/monthly-stats')
def monthly_stats():
    """Returns upload counts per month for the last 12 months — used by Chart.js."""
    if 'user_id' not in session:
        return jsonify({"error": "Unauthorized"}), 401

    conn = get_db()
    rows = conn.execute(
        """
        SELECT strftime('%Y-%m', uploaded_at) as month, COUNT(*) as count
        FROM documents
        WHERE user_id = ?
        GROUP BY month
        ORDER BY month ASC
        LIMIT 12
        """,
        (session['user_id'],)
    ).fetchall()
    conn.close()

    return jsonify([{"month": r['month'], "count": r['count']} for r in rows])


# =========================
# FOLDER ROUTES
# =========================

@app.route('/api/folders', methods=['GET'])
def list_folders():
    if 'user_id' not in session:
        return jsonify({"error": "Unauthorized"}), 401
    conn = get_db()
    folders = conn.execute(
        "SELECT id, name, created_at FROM folders WHERE user_id = ? ORDER BY name ASC",
        (session['user_id'],)
    ).fetchall()
    conn.close()
    return jsonify([{"id": f['id'], "name": f['name'], "createdAt": f['created_at']} for f in folders])


@app.route('/api/folders', methods=['POST'])
def create_folder():
    if 'user_id' not in session:
        return jsonify({"error": "Unauthorized"}), 401
    name = (request.json or {}).get('name', '').strip()
    if not name:
        return jsonify({"error": "Folder name required"}), 400
    conn = get_db()
    try:
        conn.execute(
            "INSERT INTO folders (user_id, name) VALUES (?, ?)",
            (session['user_id'], name)
        )
        conn.commit()
    finally:
        conn.close()
    log_activity(session['user_id'], f"Created folder: {name}")
    return jsonify({"message": "Folder created"})


@app.route('/api/folders/<int:folder_id>', methods=['DELETE'])
def delete_folder(folder_id):
    if 'user_id' not in session:
        return jsonify({"error": "Unauthorized"}), 401
    conn = get_db()
    folder = conn.execute(
        "SELECT name FROM folders WHERE id = ? AND user_id = ?",
        (folder_id, session['user_id'])
    ).fetchone()
    if not folder:
        conn.close()
        return jsonify({"error": "Folder not found"}), 404
    conn.execute("DELETE FROM folders WHERE id = ?", (folder_id,))
    conn.commit()
    conn.close()
    log_activity(session['user_id'], f"Deleted folder: {folder['name']}")
    return jsonify({"message": "Folder deleted"})


# =========================
# DOCUMENT ROUTES
# =========================

@app.route('/api/documents', methods=['GET'])
def get_documents():
    if 'user_id' not in session:
        return jsonify({"error": "Unauthorized"}), 401

    folder_id = request.args.get('folder_id')  # optional filter
    conn = get_db()

    if folder_id:
        docs = conn.execute(
            """
            SELECT id, doc_type, doc_name, category, favorite,
                   file_size_string, file_mime, uploaded_at, download_count, folder_id
            FROM documents WHERE user_id = ? AND folder_id = ?
            ORDER BY favorite DESC, uploaded_at DESC
            """,
            (session['user_id'], folder_id)
        ).fetchall()
    else:
        docs = conn.execute(
            """
            SELECT id, doc_type, doc_name, category, favorite,
                   file_size_string, file_mime, uploaded_at, download_count, folder_id
            FROM documents WHERE user_id = ?
            ORDER BY favorite DESC, uploaded_at DESC
            """,
            (session['user_id'],)
        ).fetchall()

    conn.close()
    return jsonify([{
        "id": doc['id'],
        "type": doc['doc_type'],
        "name": doc['doc_name'],
        "category": doc['category'],
        "favorite": bool(doc['favorite']),
        "size": doc['file_size_string'],
        "mime": doc['file_mime'],
        "uploadedAt": doc['uploaded_at'],
        "downloadCount": doc['download_count'],
        "folderId": doc['folder_id']
    } for doc in docs])


@app.route('/api/documents/upload', methods=['POST'])
def upload_document():
    if 'user_id' not in session:
        return jsonify({"error": "Unauthorized"}), 401

    # Support multiple files via 'files[]' or single 'file'
    files = request.files.getlist('files[]') or ([request.files['file']] if 'file' in request.files else [])

    if not files or files[0].filename == '':
        return jsonify({"error": "No file uploaded"}), 400

    doc_type = request.form.get('type', 'Document')
    category = request.form.get('category', 'General')
    folder_id = request.form.get('folder_id') or None

    uploaded = []
    errors = []

    for file in files:
        if not allowed_file(file.filename):
            errors.append(f"{file.filename}: Invalid file type")
            continue

        filename = secure_filename(file.filename)
        file_data = file.read()
        file_size_bytes = len(file_data)
        file_size_mb = file_size_bytes / (1024 * 1024)

        if file_size_mb > MAX_FILE_SIZE_MB:
            errors.append(f"{filename}: Exceeds {MAX_FILE_SIZE_MB}MB limit")
            continue

        # Encrypt before storing
        encrypted_data = encrypt_data(file_data)
        file_size_string = f"{file_size_mb:.2f} MB"

        conn = get_db()
        conn.execute(
            """
            INSERT INTO documents
                (user_id, folder_id, doc_type, doc_name, category,
                 file_mime, file_size_bytes, file_size_string, file_blob)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                session['user_id'], folder_id, doc_type, filename, category,
                file.content_type, file_size_bytes, file_size_string, encrypted_data
            )
        )
        conn.commit()
        conn.close()

        log_activity(session['user_id'], f"Uploaded document: {filename}")
        uploaded.append(filename)

    return jsonify({
        "message": f"Uploaded {len(uploaded)} file(s)",
        "uploaded": uploaded,
        "errors": errors
    })


@app.route('/api/documents/view/<int:doc_id>')
def view_document(doc_id):
    if 'user_id' not in session:
        return jsonify({"error": "Unauthorized"}), 401

    conn = get_db()
    doc = conn.execute(
        "SELECT file_blob, file_mime FROM documents WHERE id = ? AND user_id = ?",
        (doc_id, session['user_id'])
    ).fetchone()
    conn.close()

    if not doc:
        return jsonify({"error": "Document not found"}), 404

    decrypted = decrypt_data(bytes(doc['file_blob']))
    return send_file(io.BytesIO(decrypted), mimetype=doc['file_mime'])


@app.route('/api/documents/download/<int:doc_id>')
def download_document(doc_id):
    if 'user_id' not in session:
        return jsonify({"error": "Unauthorized"}), 401

    conn = get_db()
    doc = conn.execute(
        "SELECT doc_name, file_blob, file_mime FROM documents WHERE id = ? AND user_id = ?",
        (doc_id, session['user_id'])
    ).fetchone()

    if not doc:
        conn.close()
        return jsonify({"error": "Document not found"}), 404

    # Increment download counter
    conn.execute(
        "UPDATE documents SET download_count = download_count + 1 WHERE id = ?",
        (doc_id,)
    )
    conn.commit()
    conn.close()

    decrypted = decrypt_data(bytes(doc['file_blob']))
    log_activity(session['user_id'], f"Downloaded document: {doc['doc_name']}")

    return send_file(
        io.BytesIO(decrypted),
        mimetype=doc['file_mime'],
        as_attachment=True,
        download_name=doc['doc_name']
    )


@app.route('/api/documents/delete/<int:doc_id>', methods=['DELETE'])
def delete_document(doc_id):
    if 'user_id' not in session:
        return jsonify({"error": "Unauthorized"}), 401

    conn = get_db()
    doc = conn.execute(
        "SELECT doc_name FROM documents WHERE id = ? AND user_id = ?",
        (doc_id, session['user_id'])
    ).fetchone()

    if not doc:
        conn.close()
        return jsonify({"error": "Document not found"}), 404

    conn.execute("DELETE FROM documents WHERE id = ? AND user_id = ?", (doc_id, session['user_id']))
    conn.commit()
    conn.close()

    log_activity(session['user_id'], f"Deleted document: {doc['doc_name']}")
    return jsonify({"message": "Document deleted successfully"})


# =========================
# SEARCH DOCUMENTS
# =========================

@app.route('/api/documents/search')
def search_documents():
    if 'user_id' not in session:
        return jsonify({"error": "Unauthorized"}), 401

    keyword = request.args.get('q', '')
    conn = get_db()
    docs = conn.execute(
        """
        SELECT id, doc_name, doc_type FROM documents
        WHERE user_id = ? AND doc_name LIKE ?
        ORDER BY uploaded_at DESC
        """,
        (session['user_id'], f'%{keyword}%')
    ).fetchall()
    conn.close()

    return jsonify([{"id": d['id'], "name": d['doc_name'], "type": d['doc_type']} for d in docs])


# =========================
# FAVORITE DOCUMENTS
# =========================

@app.route('/api/documents/favorite/<int:doc_id>', methods=['PUT'])
def favorite_document(doc_id):
    if 'user_id' not in session:
        return jsonify({"error": "Unauthorized"}), 401

    conn = get_db()
    doc = conn.execute(
        "SELECT favorite FROM documents WHERE id = ? AND user_id = ?",
        (doc_id, session['user_id'])
    ).fetchone()

    if not doc:
        conn.close()
        return jsonify({"error": "Document not found"}), 404

    conn.execute(
        "UPDATE documents SET favorite = ? WHERE id = ?",
        (0 if doc['favorite'] else 1, doc_id)
    )
    conn.commit()
    conn.close()
    return jsonify({"message": "Favorite updated"})


# =========================
# ACTIVITY LOGS
# =========================

@app.route('/api/activity')
def get_activity_logs():
    if 'user_id' not in session:
        return jsonify({"error": "Unauthorized"}), 401

    conn = get_db()
    logs = conn.execute(
        """
        SELECT action, created_at FROM activity_logs
        WHERE user_id = ? ORDER BY created_at DESC LIMIT 20
        """,
        (session['user_id'],)
    ).fetchall()
    conn.close()

    return jsonify([{"action": l['action'], "time": l['created_at']} for l in logs])


# =========================
# MAIN
# =========================

if __name__ == '__main__':
    app.run(debug=True, port=5000)
