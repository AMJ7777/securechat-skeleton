# Assignment #2 - SecureChat System

**Student:** M. Asad Mehdi  
**Roll Number:** i221120  
**Course:** Information Security (CS-3002)  
**Institution:** FAST-NUCES  
**Semester:** Fall 2025  

---

## 📁 Directory Contents

```
i221120_M.AsadMehdi_A02/
├── README.md                                    (This file)
├── SUBMISSION_CHECKLIST.md                      (Pre-submission verification)
├── Implementation/
│   └── securechat/
│       ├── README.md                            (Complete project documentation)
│       ├── QUICKSTART.md                        (5-minute setup guide)
│       ├── requirements.txt                     (Python dependencies)
│       ├── schema.sql                           (MySQL database schema)
│       ├── .env.example                         (Configuration template)
│       ├── .gitignore                           (Ignore secrets and logs)
│       ├── app/
│       │   ├── client.py                        (Client implementation)
│       │   ├── server.py                        (Server implementation)
│       │   ├── common/
│       │   │   ├── protocol.py                  (Pydantic message models)
│       │   │   └── utils.py                     (Helper functions)
│       │   ├── crypto/
│       │   │   ├── aes.py                       (AES-128 encryption)
│       │   │   ├── dh.py                        (Diffie-Hellman)
│       │   │   ├── pki.py                       (Certificate validation)
│       │   │   └── sign.py                      (RSA signatures)
│       │   └── storage/
│       │       ├── db.py                        (MySQL user management)
│       │       └── transcript.py                (Session logging)
│       ├── scripts/
│       │   ├── gen_ca.py                        (Generate Root CA)
│       │   └── gen_cert.py                      (Issue certificates)
│       ├── tests/
│       │   └── manual/
│       │       └── NOTES.md                     (Testing instructions)
│       └── verify_receipt.py                    (Offline verification)
└── Documents/                                   (To be added before submission)
    ├── i221120_M.AsadMehdi_Report_A02.docx
    └── i221120_M.AsadMehdi_TestReport_A02.docx
```

---

## 🎯 Project Overview

This assignment implements a **console-based secure chat system** that demonstrates:

### Security Properties (CIANR)
✅ **Confidentiality** – AES-128 encryption  
✅ **Integrity** – SHA-256 + RSA signatures  
✅ **Authenticity** – Mutual PKI authentication  
✅ **Non-Repudiation** – Signed session transcripts  

### Key Features
- Self-built PKI (Certificate Authority)
- Mutual certificate authentication
- Encrypted registration/login (MySQL)
- Diffie-Hellman key exchange (forward secrecy)
- AES-128 encrypted messaging
- Per-message RSA signatures
- Replay attack prevention
- Offline verifiable transcripts

---

## 🚀 Quick Start

See **[Implementation/securechat/QUICKSTART.md](Implementation/securechat/QUICKSTART.md)** for a 5-minute setup guide.

### Minimal Steps:

```bash
cd Implementation/securechat

# 1. Setup
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt

# 2. Database
mysql -u root -p < schema.sql

# 3. Certificates
python scripts/gen_ca.py
python scripts/gen_cert.py

# 4. Run
python -m app.server     # Terminal 1
python -m app.client     # Terminal 2
```

---

## 📚 Documentation

| Document | Description |
|----------|-------------|
| **[Implementation/securechat/README.md](Implementation/securechat/README.md)** | Complete project documentation (setup, usage, protocol, testing) |
| **[Implementation/securechat/QUICKSTART.md](Implementation/securechat/QUICKSTART.md)** | Fast setup guide |
| **[Implementation/securechat/tests/manual/NOTES.md](Implementation/securechat/tests/manual/NOTES.md)** | Detailed testing instructions |
| **[SUBMISSION_CHECKLIST.md](SUBMISSION_CHECKLIST.md)** | Pre-submission verification checklist |

---

## 🧪 Testing

All required tests are documented in:
- **[Implementation/securechat/tests/manual/NOTES.md](Implementation/securechat/tests/manual/NOTES.md)**

Tests include:
1. ✅ PKI handshake and certificate validation
2. ✅ Invalid certificate rejection
3. ✅ Wireshark encrypted payload capture
4. ✅ Tampering detection
5. ✅ Replay attack prevention
6. ✅ Non-repudiation verification
7. ✅ Registration and login flow
8. ✅ Session key uniqueness

---

## 🔐 Security Implementation

### Cryptographic Primitives
- **AES-128 (ECB mode)** – Message encryption
- **RSA-2048** – Digital signatures and PKI
- **Diffie-Hellman (RFC 3526 Group 14)** – Key agreement
- **SHA-256** – Hashing and key derivation

### Protocol Flow
1. **Handshake:** Mutual PKI authentication
2. **Auth:** Encrypted registration/login
3. **Session:** DH key exchange
4. **Chat:** Encrypted + signed messages
5. **Teardown:** Non-repudiation receipts

---

## 📊 Assignment Requirements Met

| Requirement | Status | Implementation |
|-------------|--------|----------------|
| GitHub workflow (≥10 commits) | ✅ | Clean commit history |
| PKI setup & validation | ✅ | `scripts/gen_*.py`, `crypto/pki.py` |
| Registration/login security | ✅ | `storage/db.py`, salted SHA-256 |
| Encrypted chat (AES-128) | ✅ | `crypto/aes.py`, `crypto/dh.py` |
| Integrity/authenticity | ✅ | `crypto/sign.py`, per-message sigs |
| Non-repudiation | ✅ | `storage/transcript.py`, receipts |
| Testing & evidence | ✅ | `tests/manual/NOTES.md` |

---

## 🏗️ Technology Stack

- **Language:** Python 3.10+
- **Database:** MySQL 8.0
- **Libraries:**
  - `cryptography` – Cryptographic primitives
  - `PyMySQL` – Database connectivity
  - `pydantic` – Data validation
  - `python-dotenv` – Configuration management

---

## 📝 Submission Contents

Before submitting, ensure:
- ✅ All code files complete and tested
- ✅ `i221120_M.AsadMehdi_Report_A02.docx` written
- ✅ `i221120_M.AsadMehdi_TestReport_A02.docx` with evidence
- ✅ MySQL dump included (`securechat_dump.sql`)
- ✅ README.md updated with GitHub repository link
- ✅ No secrets committed to Git

Use **[SUBMISSION_CHECKLIST.md](SUBMISSION_CHECKLIST.md)** for final verification.

---

## 🔗 GitHub Repository

**Repository URL:** `https://github.com/yourusername/securechat-assignment`  
_(Update this link with your actual repository)_

---

## 👨‍💻 Author

**M. Asad Mehdi**  
Roll Number: i221120  
Email: i221120@nu.edu.pk  

---

## 📅 Submission Information

- **Course:** Information Security (CS-3002)
- **Assignment:** #2 - Console Based Secure Chat System
- **Instructor:** [Instructor Name]
- **Deadline:** As per GCR
- **Submission Method:** Google Classroom

---

## 🎓 Academic Integrity Statement

This assignment was completed individually in accordance with FAST-NUCES academic integrity policies. All code is original except where explicitly cited. Cryptographic primitives use standard libraries (`cryptography` package) as permitted by the assignment specifications.

---

## 📖 References

1. RFC 3526 – More Modular Exponential (MODP) Diffie-Hellman groups
2. NIST FIPS 197 – Advanced Encryption Standard (AES)
3. RFC 5280 – Internet X.509 Public Key Infrastructure
4. RFC 8017 – PKCS #1: RSA Cryptography Specifications
5. Python Cryptography Library Documentation

---

**Last Updated:** November 2025  
**Version:** 1.0  
**Status:** Ready for Submission

