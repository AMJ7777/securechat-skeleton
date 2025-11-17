# Assignment #2 Submission Checklist

**Student:** M. Asad Mehdi  
**Roll Number:** i221120  
**Course:** Information Security (CS-3002)  
**Assignment:** Console-Based Secure Chat System  

---

## 📋 Required Deliverables

### 1. ✅ Source Code (GitHub Repository)

- [x] Repository forked/created
- [x] Minimum 10 meaningful commits showing progressive development
- [x] Clear commit messages (e.g., "Add PKI validation", "Implement DH key exchange")
- [x] `.gitignore` properly configured (no secrets committed)
- [x] Repository link included in README.md

**Repository URL:** `_______________________________` _(Fill in)_

---

### 2. ✅ Code Structure and Implementation

#### PKI Setup (20% weight)
- [x] `scripts/gen_ca.py` - Root CA generation
- [x] `scripts/gen_cert.py` - Certificate issuance
- [x] `app/crypto/pki.py` - Certificate validation
- [x] Mutual authentication implemented
- [x] Signature chain verification
- [x] Expiry and CN checks
- [x] Invalid/expired certificate rejection

#### Registration & Login Security (20% weight)
- [x] `app/storage/db.py` - MySQL integration
- [x] Per-user random salt (≥16 bytes)
- [x] Salted SHA-256 hashing: `hex(sha256(salt||pwd))`
- [x] No plaintext passwords in storage or logs
- [x] Credentials encrypted during transit
- [x] Login requires valid certificate + correct password

#### Encrypted Chat (20% weight)
- [x] `app/crypto/dh.py` - Diffie-Hellman implementation
- [x] `app/crypto/aes.py` - AES-128 encryption
- [x] Session key derivation: `K = Trunc16(SHA256(Ks))`
- [x] PKCS#7 padding
- [x] Clean send/receive logic
- [x] Error handling

#### Integrity, Authenticity & Non-Repudiation (10% weight)
- [x] `app/crypto/sign.py` - RSA signatures
- [x] Per-message signature: `RSA_SIGN(SHA256(seqno||ts||ct))`
- [x] Sequence number replay defense
- [x] `app/storage/transcript.py` - Append-only logging
- [x] `verify_receipt.py` - Offline verification
- [x] SessionReceipt generation and exchange

#### Testing & Evidence (10% weight)
- [x] Wireshark PCAP or screenshots
- [x] Display filters documented
- [x] Invalid certificate test
- [x] Tampering detection test
- [x] Replay attack test
- [x] Steps reproducible by TA

---

### 3. ✅ Documentation Files

- [x] **README.md**
  - [x] Setup instructions
  - [x] Execution steps
  - [x] Configuration requirements
  - [x] Sample input/output
  - [x] GitHub repository link
  
- [x] **requirements.txt**
  - [x] All dependencies listed with versions
  - [x] Cryptography library
  - [x] MySQL connector
  - [x] Pydantic
  
- [x] **.env.example**
  - [x] Database configuration template
  - [x] Server settings
  - [x] No actual secrets

- [x] **.gitignore**
  - [x] Excludes `certs/`
  - [x] Excludes `.env`
  - [x] Excludes `*.log`, `*.json` (evidence files)
  - [x] Excludes `__pycache__/`

- [x] **schema.sql**
  - [x] Database creation script
  - [x] Users table definition
  - [x] Sample data (optional)
  - [x] Comments explaining structure

---

### 4. ✅ MySQL Database

- [x] Database dump file included
- [x] Schema shows `users` table with:
  - [x] `email VARCHAR(255)`
  - [x] `username VARCHAR(50) UNIQUE`
  - [x] `salt VARBINARY(16)`
  - [x] `pwd_hash CHAR(64)`
- [x] Sample records included
- [x] No chat messages stored in database

**Export Command Used:**
```bash
mysqldump -u root -p securechat > securechat_dump.sql
```

---

### 5. ✅ Report Document

**File:** `i221120_M.AsadMehdi_Report_A02.docx`

Should include:
- [x] Title page (name, roll number, course)
- [x] Abstract/Introduction
- [x] System architecture overview
- [x] Protocol description (phases 1-4)
- [x] Security properties explanation (CIANR)
- [x] Implementation highlights
- [x] Challenges faced and solutions
- [x] References and citations

---

### 6. ✅ Test Report Document

**File:** `i221120_M.AsadMehdi_TestReport_A02.docx`

Should include:

#### Test 1: Wireshark Capture
- [x] Screenshot of encrypted payloads
- [x] Display filter used
- [x] Explanation

#### Test 2: Invalid Certificate Rejection
- [x] Steps to create fake certificate
- [x] Screenshot of `BAD_CERT` error
- [x] Server log output

#### Test 3: Tampering Detection
- [x] Modified transcript file
- [x] Screenshot of verification failure
- [x] Explanation of hash mismatch

#### Test 4: Replay Attack Prevention
- [x] Demonstration method
- [x] Screenshot of replay detection
- [x] Security alert message

#### Test 5: Non-Repudiation
- [x] Transcript files
- [x] Receipt JSON files
- [x] Screenshot of successful verification
- [x] Screenshot of failed verification (after tampering)
- [x] Explanation of offline verification process

---

## 📦 Submission Package Structure

```
i221120_M.AsadMehdi_A02/
├── i221120_M.AsadMehdi_Report_A02.docx
├── i221120_M.AsadMehdi_TestReport_A02.docx
├── Implementation/
│   └── securechat/
│       ├── README.md (with GitHub link)
│       ├── requirements.txt
│       ├── schema.sql
│       ├── securechat_dump.sql (MySQL dump)
│       ├── app/
│       │   ├── client.py
│       │   ├── server.py
│       │   ├── common/
│       │   ├── crypto/
│       │   └── storage/
│       ├── scripts/
│       │   ├── gen_ca.py
│       │   └── gen_cert.py
│       └── verify_receipt.py
└── Evidence/
    ├── wireshark_capture.png
    ├── invalid_cert_rejection.png
    ├── tampering_detection.png
    ├── replay_attack.png
    └── non_repudiation_verification.png
```

---

## ✅ Pre-Submission Verification

### Code Quality
- [ ] All Python files have docstrings
- [ ] No TODO or FIXME comments left
- [ ] No debug print statements
- [ ] Error handling implemented
- [ ] Code follows consistent style

### Functionality
- [ ] Server starts without errors
- [ ] Client connects successfully
- [ ] Registration works
- [ ] Login works
- [ ] Messages encrypt/decrypt correctly
- [ ] Signatures verify successfully
- [ ] Receipts generate properly
- [ ] Offline verification succeeds

### Security
- [ ] No secrets in repository
- [ ] Certificates gitignored
- [ ] Database credentials in `.env` (not in code)
- [ ] No plaintext passwords in logs
- [ ] Invalid certificates rejected
- [ ] Tampering detected
- [ ] Replay attacks prevented

### Documentation
- [ ] README.md complete and clear
- [ ] Setup steps tested by fresh user
- [ ] All commands verified
- [ ] Sample outputs accurate
- [ ] GitHub link working

---

## 📊 Grading Rubric Self-Check

| Category | Max Points | Self-Assessment | Notes |
|----------|------------|-----------------|-------|
| GitHub Workflow | 20 | __/20 | ≥10 commits, README, no secrets |
| PKI Setup | 20 | __/20 | CA works, mutual auth, validation |
| Registration/Login | 20 | __/20 | Salted hashing, encrypted transit |
| Encrypted Chat | 20 | __/20 | DH + AES-128, correct padding |
| Integrity/Auth/NR | 10 | __/10 | Signatures, replay defense, receipts |
| Testing & Evidence | 10 | __/10 | All tests documented |
| **Total** | **100** | __/100 | |

**Bonus (Optional):**
- [ ] Exceptional code quality (+2)
- [ ] Additional security features (+2)
- [ ] Comprehensive testing (+1)

---

## 📤 Final Submission Steps

1. **GitHub:**
   - [ ] Push all commits
   - [ ] Verify repository is accessible
   - [ ] Update README with repository URL

2. **ZIP Creation:**
   ```bash
   cd "/Users/asadmehdi/Documents/Semester 7/InfoSec/Assignment/"
   zip -r i221120_M.AsadMehdi_A02.zip i221120_M.AsadMehdi_A02/
   ```

3. **MySQL Dump:**
   ```bash
   mysqldump -u root -p securechat > Implementation/securechat/securechat_dump.sql
   ```

4. **GCR Upload:**
   - [ ] Upload ZIP file
   - [ ] Verify file size reasonable (<50 MB)
   - [ ] Check deadline

5. **Confirmation:**
   - [ ] Received GCR submission confirmation
   - [ ] Assignment marked as submitted

---

## 🎯 Success Criteria

Your assignment is ready when:
- ✅ All files in this checklist are completed
- ✅ System runs end-to-end without errors
- ✅ All security properties demonstrated
- ✅ Test evidence collected
- ✅ Documentation clear and complete
- ✅ Repository has meaningful commit history
- ✅ No secrets committed

---

## 📞 Contact

If issues arise:
1. Check [README.md](Implementation/securechat/README.md) troubleshooting
2. Review [tests/manual/NOTES.md](Implementation/securechat/tests/manual/NOTES.md)
3. Contact instructor via GCR

---

**Good Luck! 🚀**

---

**Last Updated:** November 2025  
**Checklist Version:** 1.0

