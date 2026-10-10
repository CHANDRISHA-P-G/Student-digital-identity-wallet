# 🎓 Student Digital Identity Wallet

A secure, role-based academic credential issuance and verification platform built with Python (Flask), Cryptographic RSA-2048 signing, SHA-256 integrity hashing, and automated PDF/Image QR watermarking.

---

## 🛠️ Tech Stack

- **Backend:** Python 3, Flask, SQLite3
- **Cryptography & Security:** `cryptography` (RSA-2048 & SHA-256), `hashlib`, `base64`
- **Document Processing:** `pypdf`, `reportlab`, `Pillow` (PIL), `qrcode`
- **Frontend UI:** HTML5, Modern JavaScript (ES6+), Tailwind CSS (Glassmorphism), Lucide Icons, `jsQR`

---

## 🚀 Key Features

- **Role-Based Access Control (RBAC):** Custom registration and isolation between **College**, **Student**, and **Verifier** portals.
- **Automated QR Document Stamping:** Dynamically calculates page dimensions and burns/stamps a verification QR code and Certificate ID into the bottom-right corner of PDFs and images upon issuance.
- **Cryptographic Anti-Tampering:** Documents are signed with RSA-2048 asymmetric keys. Any post-issuance file editing breaks SHA-256 hash matching and triggers an instant **Tamper Warning**.
- **Certificate Revocation List (CRL):** Colleges can revoke credentials with custom reason logs or reactivate them. Status changes (`ACTIVE` vs `REVOKED`) sync instantly across all portals.
- **Dual Verification Modes:** Verifiers can validate credentials by entering/scanning the Certificate ID/QR code, or by uploading the original document file for cryptographic signature verification.

---

## 📂 Project Structure

```text
student-identity-wallet/
│
├── app.py                  # Flask backend, SQLite session auth, crypto & stamping engine
├── database.db             # Auto-generated database (Users, Certificates, CRL)
├── requirements.txt        # Project Python dependencies
├── README.md               # Hackathon setup and project documentation
│
├── static/
│   ├── keys/               # Generated RSA Private & Public key PEM files
│   └── uploads/            # QR-stamped issued certificate files
│
└── templates/
    └── index.html          # Glassmorphism Single Page Application frontend
