# Arcanux

A cross-platform desktop application that combines **post-quantum cryptography** with **steganography**: encrypt a file with a NIST-standardized quantum-resistant algorithm, then hide the result inside an ordinary-looking image. Two independent layers of protection — confidentiality from the math, concealment from the disguise.

> Status: MVP complete. Core crypto and steganography engines are tested (59 automated tests). GUI is functional and smoke-tested. See [Roadmap](#roadmap) and [Known Limitations](#known-limitations) below — stated up front, not discovered later.

---

## What it actually does

1. You pick a file and a carrier image (PNG, BMP, JPEG, TIFF, or WEBP — see [why output is always PNG](#known-limitations) below).
2. Arcanux encrypts the file using **ML-KEM-768** (Kyber, NIST FIPS 203) key encapsulation combined with **ChaCha20-Poly1305** authenticated encryption.
3. The encrypted result is hidden inside the carrier image's pixel data using least-significant-bit (LSB) steganography.
4. The output is a normal-looking PNG. Anyone who doesn't have your secret key sees a picture. Anyone who intercepts it and *does* suspect something still can't decrypt it without the key — and that key-breaking resistance holds even against a future large-scale quantum computer.

## Why post-quantum, and why honestly

Classical public-key encryption (RSA, ECC) is breakable by a sufficiently large quantum computer running Shor's algorithm. ML-KEM is one of the algorithms NIST standardized specifically because it resists that attack. Encrypted data captured today and stored can be decrypted later once quantum computers are capable enough ("harvest now, decrypt later") — using a post-quantum algorithm now closes that window for anything protected with this tool.

This project deliberately does **not** claim more than that. Read [`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md) for the full picture, including a real, reproducible measurement of how detectable the steganography layer actually is against a standard statistical attack (short version: it's not bulletproof, and the doc says exactly where the line is).

## Screenshots

*(Add screenshots of the Keys / Protect / Reveal tabs here once you've run the app.)*

---

## Getting Started

### Requirements

- Python 3.10+
- pip

### Install

```bash
git clone https://github.com/YOUR_USERNAME/arcanux.git
cd arcanux
pip install -r requirements.txt
```

### Run the app

```bash
python -m src.main
```

### Run the tests

```bash
pytest tests/ -v
```

### Run the steganalysis self-test

```bash
python3 tests/steganalysis_selftest.py
```

This runs a real chi-square statistical attack (Westfeld & Pfitzmann, 1999) against Arcanux's own output and prints the results — the same numbers reported in `docs/THREAT_MODEL.md`.

---

## Using it

1. **Keys tab** — generate a new identity (an ML-KEM-768 keypair), or load an existing `.arcx` keystore file. You'll set a password that protects your secret key at rest (Argon2id-derived key, ChaCha20-Poly1305 encryption). Your public key is safe to share with anyone who wants to send you a protected file — copy it from this tab. You can also **delete** a keystore from here — this overwrites the file's bytes with random data before removing it (meaningfully better than a plain delete, but see the honest caveat about SSDs in `docs/THREAT_MODEL.md`). Deleting is permanent: any file already protected for that key and not yet revealed becomes permanently unrecoverable.
2. **Protect tab** — choose a file, choose a carrier image (any common format — PNG, BMP, JPEG, TIFF, WEBP all accepted as *input*), choose a recipient (yourself, or paste someone else's public key), check capacity, and protect. The output is always a new PNG, regardless of what format the carrier was — see [Known Limitations](#known-limitations) for why that's a hard constraint, not a missing feature.
3. **Reveal tab** — choose a protected PNG, and (with your identity loaded in the Keys tab) reveal the original file.
4. **View menu** — toggle Light/Dark mode; your choice is remembered the next time you open the app.

**Important:** the carrier image needs enough pixels to hold your file. A Kyber ciphertext plus encryption overhead is already over 1,100 bytes before your actual file is counted — a tiny image (like a 100×100 profile picture) may not have room for anything. The app checks this and tells you exactly how much space you have and how much you need, rather than failing silently.

---

## Architecture

```
GUI (PySide6) → Orchestrator → ┬→ Crypto Engine (ML-KEM-768 + ChaCha20-Poly1305)
                                └→ Steganography Engine (LSB embed/extract, PNG)
```

- `src/crypto/` — `kem.py` (ML-KEM-768), `aead.py` (ChaCha20-Poly1305), `kdf.py` (HKDF + Argon2id), `container.py` (the file format tying them together)
- `src/stego/` — `capacity.py` (pre-flight capacity checking), `image_embed.py` (LSB embed/extract)
- `src/core/` — `orchestrator.py` (the full protect/reveal workflow), `keystore.py` (password-protected key storage)
- `src/gui/` — PySide6 views: Keys, Protect, Reveal, plus a background-thread worker so crypto/embedding never freezes the window

Full design rationale, the exact container file format, and the reasoning behind each choice (including *why there's no digital signature scheme in the MVP*) are in [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md).

## Security

Read [`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md) before relying on this for anything real. Short version:

- **Defended, and tested:** confidentiality (classical and quantum-resistant), tamper detection, casual visual/audio inspection.
- **Measured, not assumed:** resistance to a real chi-square steganalysis attack — results and methodology are in the doc, including a case where the attack succeeds (low-noise images) and a case where it doesn't (photographic-noise images).
- **Not defended against, stated plainly:** modern ML-based steganalysis (untested), secure memory wiping of key material, host-level compromise (keyloggers/malware), sender authentication.

## Known Limitations

- **Input carrier images can be PNG, BMP, JPEG, TIFF, or WEBP — output is always PNG.** This isn't an arbitrary restriction. Hidden data lives in the least-significant bit of each pixel value. JPEG's compression works by transforming blocks of pixels into frequency-domain coefficients and *quantizing* them — a lossy step that discards exactly the fine-grained detail LSB steganography depends on. Saving the output as JPEG would silently corrupt or destroy the hidden payload; there is no "high quality" JPEG setting that avoids this, because the quantization step exists at every quality level. PNG is lossless, so pixel values (and the bits hidden in them) survive exactly as written. If you want JPEG-compatible steganography, that requires an entirely different technique — embedding directly in the DCT coefficients during JPEG encoding (e.g. F5, JSteg) — which is a different algorithm, not a setting, and is listed as possible future work below.
- Any re-compression of the *output* PNG (including re-saving it as JPEG, or uploading through a platform that recompresses images — many social media / messaging apps do this automatically) will destroy the hidden data.
- Embedding uses sequential (non-randomized) bit order in this version — see Roadmap.
- No audio/video/document steganography yet — images only.
- No automated GUI test suite yet (core logic is fully tested; the GUI layer is currently smoke-tested only).

## Roadmap

- [ ] WAV audio steganography
- [ ] DCT-coefficient JPEG steganography (F5/JSteg-style) — a genuinely different algorithm from LSB, needed for JPEG-compatible output
- [ ] Randomized bit-distribution embedding (anti-detection improvement)
- [ ] `pytest-qt` GUI test suite
- [ ] Streaming encryption for very large files
- [ ] Cross-platform packaged builds (PyInstaller, GitHub Actions CI)
- [ ] Optional ML-DSA signing for multi-sender authentication
- [ ] Evaluation against modern ML-based steganalysis tools

## Tech Stack

Python · PySide6 · [`pqcrypto`](https://pypi.org/project/pqcrypto/) (ML-KEM-768 / PQClean) · [`cryptography`](https://cryptography.io/) (ChaCha20-Poly1305, HKDF, Argon2id) · Pillow · NumPy

## License

MIT — see [LICENSE](LICENSE).

## Disclaimer

This is a portfolio/educational project. It has not been independently audited. Don't use it to protect anything where a real, expert-reviewed security failure would cause serious harm.
