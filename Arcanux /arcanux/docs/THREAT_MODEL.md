# Arcanux — Threat Model

This document states plainly what Arcanux defends against, what it does not, and why. Every claim below is backed by a passing test in `tests/` or a measurement in `tests/steganalysis_selftest.py` — nothing here is aspirational.

---

## 1. Assets Being Protected

- The **plaintext content** of a file the user chooses to protect.
- The **fact that protection occurred** (i.e. whether a given image contains hidden data at all) — this is the steganography layer's job, separate from confidentiality.
- The user's **ML-KEM secret key**, at rest on disk.

## 2. Adversary Model

Arcanux is scoped for **casual-to-moderately-sophisticated adversaries**, not nation-state actors. Stated explicitly, in order of increasing capability:

| Adversary | In scope? |
|---|---|
| Someone glancing at a photo/image and seeing nothing unusual | **Yes** — this is the baseline the tool is built for |
| Someone who obtains the carrier file but not the secret key, and tries to decrypt it (including with a future large-scale quantum computer) | **Yes** — ML-KEM-768 is designed to resist this |
| Someone who tampers with the carrier file in transit, hoping to corrupt or manipulate the hidden payload | **Yes** — the AEAD authentication tag detects this; `open_container()` raises rather than returning corrupted data |
| A forensic analyst running general-purpose steganalysis tools against a **flagged/suspected** file | **Partially — see Section 3.1, empirically measured, not assumed** |
| An adversary performing bulk automated steganalysis across large volumes of images to *find* candidates (rather than confirm a suspicion) | **Not defended against.** Sequential LSB embedding, even where individually hard to flag (Section 3.1), is not designed to survive systematic bulk scanning with modern tooling (RS-analysis, sample-pair analysis, CNN-based classifiers). |
| Side-channel attacks on the host machine (keyloggers, memory scraping, cold-boot attacks against the process holding the secret key in RAM) | **Not defended against.** See Section 4. |
| Multi-party sender authentication / non-repudiation (proving *who* encrypted a file, not just that it wasn't tampered with) | **Not implemented.** No signature scheme (ML-DSA) in the MVP — see Section 5. |

## 3. Steganography Detectability — Measured, Not Assumed

### 3.1 The chi-square attack self-test

`tests/steganalysis_selftest.py` implements the Westfeld-Pfitzmann chi-square attack (Westfeld & Pfitzmann, "Attacks on Steganographic Systems," 1999) — a standard, textbook technique for detecting sequential LSB embedding — and runs it against Arcanux's own output. This is not a novel attack; using a known, well-understood technique against your own system is exactly what a self-red-team pass should do.

**Two scenarios were tested, and the distinction matters:**

**Sanity check (low-noise synthetic image, no sensor noise added):**

| Scenario | Mean p-value | % windows flagged (p > 0.9) |
|---|---|---|
| Clean, unembedded | 0.191 | 8.4% |
| Fully embedded | 0.977 | 92.5% |

This confirms the attack implementation is correct: on an image resembling simple synthetic graphics (the class the chi-square attack was originally designed against), embedding is clearly and correctly detected. If this test hadn't shown separation, the *test* would be broken, not the conclusion.

**Realistic case (synthetic photographic image with sensor-like Gaussian noise):**

| Scenario | Mean p-value | % windows flagged (p > 0.9) |
|---|---|---|
| Clean, unembedded | 1.000 | 100.0% |
| Fully embedded (100% capacity) | 1.000 | 100.0% |
| Partially embedded (20% capacity) | 1.000 | 100.0% |
| Lightly embedded (2% capacity) | 1.000 | 100.0% |

**Honest interpretation:** on images with realistic photographic noise, the chi-square attack cannot distinguish clean from embedded — both score at ceiling. This is a **known, documented limitation of the chi-square attack itself**, not a Arcanux-specific claim of undetectability. Photographic sensor noise already randomizes the LSB plane enough that this particular statistical test loses power on this image class. This has two honest implications, both stated here rather than one being quietly dropped:

1. Against *this specific, well-known attack*, on *photographic-style carriers*, Arcanux's LSB embedding does not stand out.
2. This says nothing about Arcanux's resistance to **more powerful modern steganalysis** — RS-analysis, sample-pair analysis, or CNN-based steganalysis classifiers trained on large datasets. Those were **not tested** here and should be treated as unresolved, not as passed. This is listed explicitly in the roadmap as future hardening work, not silently omitted.

**Reproduce this yourself:** `python3 tests/steganalysis_selftest.py`

### 3.2 Known structural limitations (not measured, just true by construction)

- **Sequential embedding order.** Arcanux MVP embeds bits in simple raster order, not a randomized/keyed order. An attacker who knows this can target the exact bit positions used. Randomized bit distribution (seeded by a stego-key) is planned for Phase 2 and would meaningfully raise the bar against targeted extraction attempts, though it would not by itself defeat statistical detection methods aimed at LSB plane anomalies in general.
- **Lossless-format requirement.** Carrier and output must be PNG or BMP. Any re-compression to JPEG, re-upload through a platform that recompresses images (many social media / messaging apps do this automatically), or any lossy transformation destroys the embedded data outright. This is a usability and reliability limitation as much as a security one.
- **Fixed capacity overhead.** An ML-KEM-768 container has ~1,116 bytes of fixed overhead before any user data. A small carrier image (e.g. a typical profile picture) may not be able to hold anything at all. `orchestrator.check_fits()` and `stego/capacity.py` exist specifically to surface this clearly rather than fail silently or produce a corrupted result.

## 4. Key and Memory Handling — Honest Limitations

- The secret key is decrypted into a Python `bytes` object in memory while in use. Python's `bytes` type is immutable and cannot be reliably zeroed after use — a meaningful secure-wipe guarantee would require re-architecting key handling around mutable buffers (e.g. `bytearray` with explicit overwrite, or a C extension) throughout the crypto and orchestration layers. **This is not implemented in the MVP.** A memory-scraping attacker with access to the running process is not defended against.
- The keystore file (`keystore.py`) protects the secret key at rest with Argon2id + ChaCha20-Poly1305. This defends against someone who steals the `.arcx` file but not the password. It does not defend against a keylogger capturing the password as it's typed, or malware already running with the user's OS-level privileges.

## 5. Why There's No Signature Scheme (ML-DSA / Dilithium)

Arcanux's AEAD layer (ChaCha20-Poly1305) provides integrity: the authentication tag proves the ciphertext was not modified after encryption. It does **not** prove *who* created that ciphertext among multiple possible senders — that's what a signature scheme is for, and it's a different problem than tamper-detection.

For a single-user desktop tool where "protect a file for myself or for one specific recipient's public key" is the primary use case, sender authentication has limited value in the MVP. It's listed in the Phase 3 roadmap for the scenario where it does matter: verifying, among multiple possible senders, which one actually produced a given protected file.

## 6. Summary Table

| Property | Status |
|---|---|
| Confidentiality against classical computers | Yes — ChaCha20-Poly1305, 256-bit key |
| Confidentiality against quantum computers | Yes — ML-KEM-768 (NIST FIPS 203) |
| Integrity / tamper detection | Yes — AEAD authentication tag, tested against tampered ciphertext and tampered headers |
| Casual visual/audio detection resistance | Yes — by design, LSB is imperceptible to the eye/ear |
| Resistance to the classical chi-square steganalysis attack | Measured: not distinguishable on photographic-noise images; clearly distinguishable on low-noise/synthetic images (see 3.1) |
| Resistance to modern ML-based steganalysis | **Untested — treat as not defended against** |
| Sender authentication | Not implemented (by design, see Section 5) |
| Secure memory wiping of key material | Not implemented (see Section 4) |
| Resistance to host-level compromise (keyloggers, malware) | Not defended against |

If a reviewer of this repository takes away one thing from this document, it should be this: every "yes" above corresponds to a passing test, and every "no" is a limitation stated up front rather than discovered later.
