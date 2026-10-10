import os
import sqlite3
import hashlib
import qrcode
import base64
import io
from datetime import datetime
from flask import Flask, render_template, request, jsonify
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from PIL import Image

# PDF Manipulation and Stamping Libraries
from pypdf import PdfReader, PdfWriter
from reportlab.pdfgen import canvas
from reportlab.lib.pagesizes import letter

app = Flask(__name__)
app.secret_key = 'super-secret-hackathon-key-edu-vault'

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
UPLOAD_FOLDER = os.path.join(BASE_DIR, 'static', 'uploads')
KEYS_FOLDER = os.path.join(BASE_DIR, 'static', 'keys')
DATABASE = os.path.join(BASE_DIR, 'database.db')

os.makedirs(UPLOAD_FOLDER, exist_ok=True)
os.makedirs(KEYS_FOLDER, exist_ok=True)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

# ----------------------------------------------------
# DATABASE SETUP
# ----------------------------------------------------
def get_db():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db()
    cursor = conn.cursor()

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            role TEXT NOT NULL
        )
    ''')

    # Certificates table supporting status ('ACTIVE' or 'REVOKED') and revocation_reason
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS certificates (
            cert_id TEXT PRIMARY KEY,
            student_email TEXT NOT NULL,
            student_name TEXT NOT NULL,
            course_name TEXT NOT NULL,
            issue_date TEXT NOT NULL,
            file_hash TEXT NOT NULL,
            signature TEXT NOT NULL,
            file_path TEXT NOT NULL,
            qr_base64 TEXT NOT NULL,
            status TEXT DEFAULT 'ACTIVE',
            revocation_reason TEXT DEFAULT ''
        )
    ''')

    # Seed Default Accounts for Hackathon Demo
    cursor.execute("INSERT OR IGNORE INTO users (name, email, password, role) VALUES ('National University', 'college@univ.edu', 'college123', 'college')")
    cursor.execute("INSERT OR IGNORE INTO users (name, email, password, role) VALUES ('Alex Vance', 'student@univ.edu', 'student123', 'student')")

    conn.commit()
    conn.close()

init_db()

# ----------------------------------------------------
# CRYPTOGRAPHY & QR STAMPING ENGINE
# ----------------------------------------------------
PRIVATE_KEY_PATH = os.path.join(KEYS_FOLDER, 'private.pem')
PUBLIC_KEY_PATH = os.path.join(KEYS_FOLDER, 'public.pem')

def setup_keys():
    if not os.path.exists(PRIVATE_KEY_PATH) or not os.path.exists(PUBLIC_KEY_PATH):
        priv_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        pub_key = priv_key.public_key()

        with open(PRIVATE_KEY_PATH, 'wb') as f:
            f.write(priv_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            ))
        with open(PUBLIC_KEY_PATH, 'wb') as f:
            f.write(pub_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            ))

setup_keys()

def compute_sha256(data_bytes):
    return hashlib.sha256(data_bytes).hexdigest()

def sign_data(data_bytes):
    with open(PRIVATE_KEY_PATH, 'rb') as f:
        priv_key = serialization.load_pem_private_key(f.read(), password=None)
    sig = priv_key.sign(
        data_bytes,
        padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
        hashes.SHA256()
    )
    return base64.b64encode(sig).decode('utf-8')

def verify_sig(data_bytes, sig_b64):
    try:
        with open(PUBLIC_KEY_PATH, 'rb') as f:
            pub_key = serialization.load_pem_public_key(f.read())
        sig = base64.b64decode(sig_b64)
        pub_key.verify(
            sig,
            data_bytes,
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
            hashes.SHA256()
        )
        return True
    except Exception:
        return False

def generate_qr_pil(cert_id):
    qr = qrcode.QRCode(version=1, box_size=6, border=1)
    qr.add_data(cert_id)
    qr.make(fit=True)
    return qr.make_image(fill_color="#000000", back_color="#ffffff").convert('RGB')

def make_qr_base64(cert_id):
    qr_img = generate_qr_pil(cert_id)
    buf = io.BytesIO()
    qr_img.save(buf, format="PNG")
    return base64.b64encode(buf.getvalue()).decode('utf-8')

def stamp_qr_onto_file(file_bytes, filename, cert_id):
    """
    Stamps the verification QR code onto the bottom-right corner of PDF or Image certificates.
    """
    ext = os.path.splitext(filename)[1].lower()
    qr_pil = generate_qr_pil(cert_id)

    if ext == '.pdf':
        try:
            qr_buf = io.BytesIO()
            qr_pil.save(qr_buf, format="PNG")
            qr_buf.seek(0)

            overlay_buf = io.BytesIO()
            c = canvas.Canvas(overlay_buf, pagesize=letter)
            c.drawImage(qr_buf, 470, 30, width=90, height=90)
            c.drawString(470, 20, f"ID: {cert_id}")
            c.save()
            overlay_buf.seek(0)

            reader = PdfReader(io.BytesIO(file_bytes))
            writer = PdfWriter()
            overlay_reader = PdfReader(overlay_buf)
            overlay_page = overlay_reader.pages[0]

            for i, page in enumerate(reader.pages):
                if i == 0:
                    page.merge_page(overlay_page)
                writer.add_page(page)

            stamped_buf = io.BytesIO()
            writer.write(stamped_buf)
            return stamped_buf.getvalue()
        except Exception as e:
            print("PDF Stamp fallback:", e)
            return file_bytes

    elif ext in ['.png', '.jpg', '.jpeg']:
        try:
            base_img = Image.open(io.BytesIO(file_bytes)).convert('RGB')
            qr_resized = qr_pil.resize((120, 120))
            
            pos_x = base_img.width - 140
            pos_y = base_img.height - 140
            if pos_x > 0 and pos_y > 0:
                base_img.paste(qr_resized, (pos_x, pos_y))

            out_buf = io.BytesIO()
            base_img.save(out_buf, format="PNG" if ext == '.png' else "JPEG")
            return out_buf.getvalue()
        except Exception as e:
            print("Image Stamp fallback:", e)
            return file_bytes

    return file_bytes

# ----------------------------------------------------
# API ROUTES
# ----------------------------------------------------

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/api/signup', methods=['POST'])
def signup():
    data = request.get_json()
    name, email, password, role = data.get('name'), data.get('email'), data.get('password'), data.get('role')
    if not all([name, email, password, role]):
        return jsonify({'success': False, 'message': 'All fields are required!'}), 400

    try:
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute("INSERT INTO users (name, email, password, role) VALUES (?, ?, ?, ?)", (name, email, password, role))
        conn.commit()
        conn.close()
        return jsonify({'success': True, 'message': 'Account created successfully! Please log in.'}), 201
    except sqlite3.IntegrityError:
        return jsonify({'success': False, 'message': 'Email address is already registered!'}), 400

@app.route('/api/login', methods=['POST'])
def login():
    data = request.get_json()
    email, password = data.get('email'), data.get('password')
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE email = ? AND password = ?", (email, password))
    user = cursor.fetchone()
    conn.close()

    if user:
        return jsonify({'success': True, 'name': user['name'], 'email': user['email'], 'role': user['role']}), 200
    return jsonify({'success': False, 'message': 'Invalid email or password'}), 401

# College: Issue Certificate (with Auto QR Stamping)
@app.route('/api/issue-certificate', methods=['POST'])
def issue_cert():
    student_email = request.form.get('student_email')
    course_name = request.form.get('course_name')
    cert_file = request.files.get('file')

    if not all([student_email, course_name, cert_file]):
        return jsonify({'success': False, 'message': 'All fields are required'}), 400

    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT name FROM users WHERE email = ? AND role = 'student'", (student_email,))
    student = cursor.fetchone()

    if not student:
        conn.close()
        return jsonify({'success': False, 'message': 'Student email not found! Have the student register first.'}), 404

    student_name = student['name']
    raw_file_bytes = cert_file.read()
    temp_hash = compute_sha256(raw_file_bytes)
    cert_id = "CERT-" + temp_hash[:10].upper()

    cursor.execute("SELECT cert_id FROM certificates WHERE cert_id = ?", (cert_id,))
    if cursor.fetchone():
        conn.close()
        return jsonify({'success': False, 'message': 'This certificate file is already registered!'}), 400

    # STAMP QR CODE ONTO FILE BEFORE SAVING
    stamped_bytes = stamp_qr_onto_file(raw_file_bytes, cert_file.filename, cert_id)
    final_file_hash = compute_sha256(stamped_bytes)

    file_ext = os.path.splitext(cert_file.filename)[1]
    saved_filename = f"{cert_id}{file_ext}"
    filepath = os.path.join(app.config['UPLOAD_FOLDER'], saved_filename)
    
    with open(filepath, 'wb') as f:
        f.write(stamped_bytes)

    sig_b64 = sign_data(stamped_bytes)
    qr_b64 = make_qr_base64(cert_id)
    issue_date = datetime.now().strftime("%Y-%m-%d %H:%M")

    cursor.execute('''
        INSERT INTO certificates (cert_id, student_email, student_name, course_name, issue_date, file_hash, signature, file_path, qr_base64, status)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'ACTIVE')
    ''', (cert_id, student_email, student_name, course_name, issue_date, final_file_hash, sig_b64, saved_filename, qr_b64))

    conn.commit()
    conn.close()

    return jsonify({'success': True, 'message': f'Issued & QR-Stamped Certificate for {student_name}!'}), 201

# College: View Issued Certificates History
@app.route('/api/college/history', methods=['GET'])
def college_history():
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT cert_id, student_name, student_email, course_name, issue_date, status, revocation_reason FROM certificates ORDER BY issue_date DESC")
    certs = cursor.fetchall()
    conn.close()
    return jsonify([dict(c) for c in certs]), 200

# College: Revoke Certificate (CRL Feature)
@app.route('/api/college/revoke/<cert_id>', methods=['POST'])
def revoke_certificate(cert_id):
    data = request.get_json() or {}
    reason = data.get('reason', 'Academic misconduct / Administrative revocation')

    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("UPDATE certificates SET status = 'REVOKED', revocation_reason = ? WHERE cert_id = ?", (reason, cert_id))
    conn.commit()
    conn.close()
    return jsonify({'success': True, 'message': f'Certificate {cert_id} has been REVOKED.'}), 200

# College: Reactivate Certificate
@app.route('/api/college/reactivate/<cert_id>', methods=['POST'])
def reactivate_certificate(cert_id):
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("UPDATE certificates SET status = 'ACTIVE', revocation_reason = '' WHERE cert_id = ?", (cert_id,))
    conn.commit()
    conn.close()
    return jsonify({'success': True, 'message': f'Certificate {cert_id} has been REACTIVATED.'}), 200

# College: Delete Issued Certificate Record
@app.route('/api/college/delete/<cert_id>', methods=['DELETE'])
def delete_certificate(cert_id):
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT file_path FROM certificates WHERE cert_id = ?", (cert_id,))
    cert = cursor.fetchone()

    if cert:
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], cert['file_path'])
        if os.path.exists(filepath):
            os.remove(filepath)

        cursor.execute("DELETE FROM certificates WHERE cert_id = ?", (cert_id,))
        conn.commit()
        conn.close()
        return jsonify({'success': True, 'message': 'Record deleted permanently.'}), 200

    conn.close()
    return jsonify({'success': False, 'message': 'Certificate record not found.'}), 404

# Student: Fetch My Wallet Records (Includes status & revocation_reason)
@app.route('/api/student/wallet/<email>', methods=['GET'])
def student_wallet(email):
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("""
        SELECT cert_id, course_name, issue_date, file_path, qr_base64, status, revocation_reason 
        FROM certificates 
        WHERE student_email = ?
    """, (email,))
    certs = cursor.fetchall()
    conn.close()
    return jsonify([dict(c) for c in certs]), 200

# Public: Verify Certificate by ID
@app.route('/api/verify/id/<cert_id>', methods=['GET'])
def verify_by_id(cert_id):
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM certificates WHERE cert_id = ?", (cert_id,))
    cert = cursor.fetchone()
    conn.close()

    if not cert:
        return jsonify({'valid': False, 'message': 'No matching record found in official university database!'}), 404

    # Check Revocation Status
    if cert['status'] == 'REVOKED':
        return jsonify({
            'valid': False,
            'revoked': True,
            'cert_id': cert['cert_id'],
            'student_name': cert['student_name'],
            'course_name': cert['course_name'],
            'reason': cert['revocation_reason'] or 'Revoked by Issuing University',
            'message': 'CRITICAL WARNING: This certificate has been REVOKED by the issuing institution!'
        }), 200

    filepath = os.path.join(app.config['UPLOAD_FOLDER'], cert['file_path'])
    if not os.path.exists(filepath):
        return jsonify({'valid': False, 'message': 'Source record file is missing on server.'}), 500

    with open(filepath, 'rb') as f:
        file_bytes = f.read()

    hash_ok = (compute_sha256(file_bytes) == cert['file_hash'])
    sig_ok = verify_sig(file_bytes, cert['signature'])

    if hash_ok and sig_ok:
        return jsonify({
            'valid': True,
            'cert_id': cert['cert_id'],
            'student_name': cert['student_name'],
            'course_name': cert['course_name'],
            'issue_date': cert['issue_date'],
            'status': cert['status']
        }), 200

    return jsonify({'valid': False, 'message': 'Security Warning: File contents have been modified or corrupted!'}), 200

# Public: Verify Certificate by File Upload
@app.route('/api/verify/file', methods=['POST'])
def verify_by_file():
    if 'file' not in request.files:
        return jsonify({'valid': False, 'message': 'No document uploaded'}), 400

    file = request.files['file']
    uploaded_bytes = file.read()
    uploaded_hash = compute_sha256(uploaded_bytes)

    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM certificates WHERE file_hash = ?", (uploaded_hash,))
    cert = cursor.fetchone()
    conn.close()

    if not cert:
        return jsonify({'valid': False, 'message': 'Tamper Alert: Uploaded document does not match any authentic record!'}), 200

    if cert['status'] == 'REVOKED':
        return jsonify({
            'valid': False,
            'revoked': True,
            'cert_id': cert['cert_id'],
            'student_name': cert['student_name'],
            'reason': cert['revocation_reason'] or 'Revoked by Issuing University',
            'message': 'REVOKED DOCUMENT: Matches record signature but has been voided by the university!'
        }), 200

    sig_ok = verify_sig(uploaded_bytes, cert['signature'])

    return jsonify({
        'valid': sig_ok,
        'cert_id': cert['cert_id'],
        'student_name': cert['student_name'],
        'course_name': cert['course_name'],
        'issue_date': cert['issue_date'],
        'status': cert['status'],
        'message': 'Official Original Document' if sig_ok else 'Invalid Cryptographic Signature'
    }), 200

if __name__ == '__main__':
    print("Running EduVault Server on http://127.0.0.1:5000 ...")
    app.run(debug=True, port=5000)