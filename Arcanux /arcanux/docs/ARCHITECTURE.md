# Arcanux — Architecture & Roadmap

*A cross-platform desktop application combining post-quantum cryptography with steganography for secure, deniable data protection.*

> Working name: **Arcanux**. Rename freely — `crypto_stego`, `Obscura-PQ`, `Kyberveil` all fit. What matters is the substance underneath.

---

## 1. Executive Summary

Arcanux lets a user take a file, encrypt it with a post-quantum key encapsulation mechanism (ML-KEM / Kyber), and hide the resulting ciphertext inside an ordinary-looking image or audio file. The output is a carrier file that looks unremarkable to a human or a casual scan, and even if intercepted and identified as containing hidden data, the payload remains protected by quantum-resistant encryption.

Two independent layers of defense:

- **Layer 1 — Confidentiality**: ML-KEM-768 key encapsulation + ChaCha20-Poly1305 AEAD for the actual data.
- **Layer 2 — Concealment**: LSB-based steganography (with entropy-aware placement) hiding the ciphertext inside a PNG/BMP image or WAV audio file.

Breaking the system requires *both* finding the hidden payload *and* breaking post-quantum-resistant encryption. That's the pitch, and it's a legitimate one — provided the threat model attached to it is honest.

---

## 2. Threat Model (state this explicitly in the repo — don't skip it)

**In scope / defended against:**
- Casual visual/audio inspection of the carrier file (a person looking at the image sees nothing wrong)
- Basic file-property analysis (file size, metadata, checksums matching a "clean" original)
- An attacker who obtains the carrier file but not the private key — cannot decrypt even with quantum computing resources (ML-KEM resistance)
- Passive network interception if the carrier is transmitted

**Explicitly out of scope for MVP (document this — it's a strength, not a weakness):**
- Dedicated statistical steganalysis (chi-square attacks, RS analysis) by a trained analyst — LSB is detectable by these tools; this is a known, documented limitation
- Side-channel attacks on the host machine (keyloggers, memory scraping, cold-boot attacks)
- Multi-party sender authentication (no signature scheme in MVP — see Section 4)
- Nation-state-level adversaries with steganalysis + traffic analysis capability

Being explicit about what you *don't* defend against is what separates a security project from a security toy. Put this table in the README verbatim.

---

## 3. System Architecture

```
┌─────────────────────────────────────────────────────────┐
│                    GUI Layer (PySide6)                   │
│   Encrypt/Embed View | Decrypt/Extract View | Key Mgmt    │
└───────────────────────┬─────────────────────────────────┘
                         │
┌───────────────────────▼─────────────────────────────────┐
│              Orchestration / Workflow Layer               │
│   Validates inputs → calls crypto engine → calls embed    │
│   engine → writes output → handles errors                 │
└──────────┬────────────────────────────┬───────────────────┘
           │                            │
┌──────────▼──────────┐      ┌──────────▼──────────────────┐
│   Crypto Engine       │      │   Steganography Engine       │
│  - ML-KEM-768 keygen  │      │  - Capacity calculator       │
│  - Encapsulate/       │      │  - LSB embed (image)         │
│    Decapsulate         │      │  - LSB embed (audio/WAV)     │
│  - HKDF key derivation│      │  - Extraction                │
│  - ChaCha20-Poly1305  │      │  - Format-specific I/O       │
│    AEAD encrypt/decrypt│      │    (Pillow, wave/numpy)     │
└──────────┬────────────┘      └───────────────┬──────────────┘
           │                                    │
┌──────────▼────────────────────────────────────▼──────────┐
│                   File Format / Container Layer            │
│   Custom container header: magic bytes, version,           │
│   algorithm IDs, KEM ciphertext, nonce, AEAD ciphertext,   │
│   integrity check                                          │
└─────────────────────────────────────────────────────────┘
```

**Trust boundary**: Everything left of the GUI is untrusted input (file paths, carrier files, passwords). The crypto engine never trusts the steganography engine's output without re-verifying the AEAD tag on extraction — assume the carrier could be corrupted or tampered with in transit.

---

## 4. Cryptographic Design

| Component | Choice | Why |
|---|---|---|
| Key Encapsulation | **ML-KEM-768** (Kyber, NIST FIPS 203) | Standardized, quantum-resistant, good speed/security balance for desktop use |
| Symmetric Cipher | **ChaCha20-Poly1305** (AEAD) | Fast in software (no AES-NI dependency issues across platforms), authenticated — gives integrity without a signature scheme |
| Key Derivation | **HKDF-SHA256** | Derives the AEAD key from the ML-KEM shared secret cleanly |
| Password-based key protection (for storing private keys) | **Argon2id** | Memory-hard, resists GPU/ASIC brute force on the user's local keystore password |
| Library | `liboqs-python` (Open Quantum Safe) for ML-KEM; `cryptography` (pyca) for AEAD/HKDF/Argon2id | Both are actively maintained, audited-adjacent, and this pairing is exactly how real hybrid PQC systems are built today |

**File container format (v1):**

```
[4 bytes]  Magic: "ARCX"
[1 byte]   Version
[1 byte]   Algorithm ID (0x01 = ML-KEM-768 + ChaCha20-Poly1305)
[N bytes]  ML-KEM ciphertext (encapsulated key)
[12 bytes] AEAD nonce
[M bytes]  AEAD ciphertext (encrypted file data + auth tag appended)
```

This entire container is what gets embedded into the carrier — not the raw file. Document this format precisely in `docs/FILE_FORMAT.md`; it's the kind of artifact that makes a resume project look like real engineering rather than a script.

**Why no signatures in MVP, and why that's defensible**: the AEAD tag already proves the ciphertext wasn't modified after encryption. A signature would prove *who* encrypted it — irrelevant for a single-user local encryption tool. Flagged in roadmap as a Phase 3 addition (ML-DSA) for the multi-user/verification use case, not because MVP is incomplete without it.

---

## 5. Steganography Design (MVP scope: Images + WAV audio)

**Image (PNG/BMP) — LSB embedding:**
- Use the least significant bit of each RGB channel (optionally skip the alpha channel)
- Capacity: `(width × height × 3) / 8` bytes usable, minus header overhead
- **Critical constraint to document**: ML-KEM-768 ciphertexts are not tiny (~1088 bytes for the encapsulated key alone, plus nonce, plus AEAD ciphertext of the actual payload). A small carrier image cannot hold much. Build a capacity checker into the GUI that warns the user *before* they try to encrypt a 50MB file into a 200×200 pixel image and wonder why it failed.
- PNG only for output (lossless) — reject JPEG as a carrier for MVP; JPEG's lossy compression destroys LSB data. State this limitation clearly.

**Audio (WAV) — LSB embedding:**
- Same LSB principle applied to 16-bit PCM sample data
- Capacity: `(num_samples × bits_per_sample_used) / 8` bytes
- Reject compressed formats (MP3) for the same reason as JPEG

**Randomized bit distribution (basic anti-detection improvement over naive sequential LSB)**: derive a pseudo-random pixel/sample selection order from a seed (can be derived from the password or a separate stego-key), so the embedded bits aren't just the first N pixels in raster order. This is a meaningful, well-understood improvement that's easy to implement and worth highlighting as a design decision, not just "we used LSB."

---

## 6. Tech Stack

| Layer | Choice |
|---|---|
| GUI Framework | PySide6 (Qt for Python) |
| Crypto | `liboqs-python`, `cryptography` (pyca) |
| Image handling | Pillow |
| Audio handling | `wave` (stdlib) + `numpy` for fast bit manipulation |
| Packaging | PyInstaller (Windows/macOS/Linux binaries) |
| CI/CD | GitHub Actions (build matrix: windows-latest, macos-latest, ubuntu-latest) |
| Testing | `pytest` + `pytest-qt` for GUI testing |

---

## 7. Project Structure

```
arcanux/
├── src/
│   ├── crypto/
│   │   ├── kem.py              # ML-KEM keygen, encapsulate, decapsulate
│   │   ├── aead.py             # ChaCha20-Poly1305 wrapper
│   │   ├── kdf.py              # HKDF, Argon2id
│   │   └── container.py        # File container format read/write
│   ├── stego/
│   │   ├── image_embed.py
│   │   ├── audio_embed.py
│   │   └── capacity.py
│   ├── gui/
│   │   ├── main_window.py
│   │   ├── encrypt_view.py
│   │   ├── decrypt_view.py
│   │   └── key_manager_view.py
│   ├── core/
│   │   └── orchestrator.py     # Ties crypto + stego together
│   └── main.py
├── tests/
│   ├── test_crypto.py
│   ├── test_stego.py
│   └── test_container.py
├── docs/
│   ├── FILE_FORMAT.md
│   ├── THREAT_MODEL.md
│   ├── ARCHITECTURE.md          # This document, refined
│   └── USER_GUIDE.md
├── .github/workflows/ci.yml
├── requirements.txt
├── LICENSE
└── README.md
```

---

## 8. MVP Definition (Phase 1)

Ship exactly this, working end-to-end, before touching anything else:

1. Generate ML-KEM-768 keypair, store private key encrypted with Argon2id-derived key from a user password
2. Encrypt a file (any type, reasonable size limit e.g. 5MB for MVP) using recipient's public key
3. Embed the resulting container into a PNG carrier image, with a pre-flight capacity check
4. Extract the container from the PNG and decrypt using the private key + password
5. Basic PySide6 GUI: pick file, pick carrier, pick/generate keys, one "Protect" button, one "Reveal" button
6. Round-trip test suite proving encrypt→embed→extract→decrypt is lossless and correct

Nothing else. No audio, no PDF, no fancy UI theming. A working MVP with an honest README beats an ambitious half-built repo every time a recruiter opens it.

---

## 9. Roadmap

**Phase 1 — MVP** *(above)*
Image steganography + ML-KEM + ChaCha20-Poly1305, functional GUI, core test suite.

**Phase 2 — Expand carriers & UX**
- WAV audio steganography
- Randomized bit-distribution (anti-detection improvement)
- Drag-and-drop GUI, progress bars for large files, capacity meter
- Larger file size support with streaming encryption (don't load 500MB into RAM at once)

**Phase 3 — Hardening**
- Security testing pass (see Section 10)
- Steganalysis resistance testing (run your own output through chi-square/RS analysis tools, document results honestly)
- Optional ML-DSA signing for sender authentication (multi-user scenario)
- Secure memory wiping for keys/passwords in memory

**Phase 4 — Packaging & release**
- PyInstaller builds for Windows/macOS/Linux
- Code signing (or documented explanation of why unsigned, for a resume project)
- GitHub Actions CI: lint, test, build matrix on every PR
- Versioned releases, CHANGELOG

**Phase 5 — Stretch goals (only if Phases 1-4 are solid)**
- PDF/DOCX carrier support
- Video (frame-based LSB) carrier support
- CLI companion tool alongside the GUI

---

## 10. Security & QA Testing Strategy

- **Functional**: round-trip correctness across file types and sizes, edge cases (empty files, files larger than carrier capacity, corrupted carriers)
- **Cryptanalysis self-check**: verify no key/nonce reuse, verify AEAD tag rejection on tampered ciphertext, verify KEM shared secrets are never logged or written to disk in plaintext
- **Steganalysis self-check**: run your own carrier outputs through open-source steganalysis tools (e.g. `StegExpose`) and document the detection rate honestly in `docs/THREAT_MODEL.md` — this single act of self-red-teaming will do more for your credibility than any feature
- **Cross-platform**: verify identical behavior on Windows/macOS/Linux, watch for line-ending and file-path issues
- **Performance**: benchmark large-file handling, memory usage during embed/extract

---

## 11. Documentation Deliverables (for the GitHub repo)

- `README.md` — project pitch, screenshots, quickstart, honest threat model summary
- `docs/ARCHITECTURE.md` — this document, refined post-build
- `docs/FILE_FORMAT.md` — exact byte-level container spec
- `docs/THREAT_MODEL.md` — expanded Section 2, plus self-red-team steganalysis results
- `docs/USER_GUIDE.md` — screenshots, step-by-step usage
- `CONTRIBUTING.md` — if you want it to look actively maintained
- `LICENSE` — MIT or Apache 2.0 recommended for a portfolio project (permissive, widely recognized by reviewers)

---

## 12. Role Ownership Map

Useful for your commit history and PR descriptions — a recruiter who sees commits tagged with clear ownership ("crypto: implement ML-KEM keygen", "stego: add capacity checker") reads as someone who thinks in systems, not just code.

| Role | Owns |
|---|---|
| Security Architect | Sections 2, 3 — threat model, trust boundaries |
| Cryptography Engineer | Section 4 — KEM, AEAD, KDF implementation |
| Steganography Engineer | Section 5 — embedding/extraction algorithms |
| Backend/Core Engineer | Orchestrator, container format, file handling |
| Desktop App Developer | GUI layer, PySide6 views |
| DevSecOps Engineer | CI/CD, packaging, dependency scanning (`pip-audit`) |
| QA/Security Tester | Section 10 test suite |
| Documentation Engineer | Section 11 deliverables |

---

*Next decision point: once this structure is approved, the build order is Crypto Engine → Container Format → Stego Engine → Orchestrator → GUI, in that order, because each layer needs the one below it tested and working first. Say the word and Phase 1 code starts.*
