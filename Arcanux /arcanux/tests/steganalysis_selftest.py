"""
Steganalysis self-red-team: the Westfeld-Pfitzmann chi-square attack
against sequential LSB embedding.

This is not a unit test in the pass/fail sense — it's a measurement.
The point is to find out, honestly, how detectable Arcanux's MVP
image steganography actually is, and write the real number into
docs/THREAT_MODEL.md instead of a hand-waved "LSB is known to be
detectable."

How the chi-square attack works (briefly): sequential LSB embedding
flips the least significant bit of pixel values in the order they're
visited. For a fully/heavily embedded region, this tends to equalize
the frequency of "pair of values" that differ only in their LSB (e.g.
how often value 84 appears vs value 85). In a natural, unmodified
image, these paired frequencies are usually unequal. The chi-square
statistic measures how close the observed frequencies are to the
"equalized" pattern predicted by LSB embedding. A high p-value (close
to 1) across a region is evidence that region has embedded data with
close to full bit-density; the statistic naturally trails off in
un-embedded regions of an image (e.g. the tail after a message ends).

Reference: Westfeld, A., & Pfitzmann, A. (1999). "Attacks on Steganographic
Systems." This is a textbook attack, not novel research — using it here
to self-evaluate rather than to defeat someone else's system.
"""

import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import numpy as np
from PIL import Image
from scipy import stats

from src.stego import image_embed


def chi_square_lsb_scores(channel_values: np.ndarray, window: int = 2000, step: int = 500) -> list[float]:
    """
    Slide a window across a flattened array of single-channel pixel
    values, computing the chi-square p-value for LSB-pair equalization
    in each window. Returns a list of p-values (one per window
    position). A value near 1.0 means "this window's LSB-pair
    frequencies look exactly like what full LSB embedding produces" —
    strong detection signal. A value near 0 means "looks like a
    natural, non-embedded image."
    """
    scores = []
    n = len(channel_values)
    for start in range(0, max(n - window, 1), step):
        segment = channel_values[start:start + window]
        if len(segment) < window:
            break

        # Build histogram of the 256 possible byte values in this window
        hist = np.bincount(segment, minlength=256).astype(np.float64)

        # Pair up values that differ only in the LSB: (0,1), (2,3), ... (254,255)
        pairs_even = hist[0::2]
        pairs_odd = hist[1::2]
        observed = pairs_even
        expected = (pairs_even + pairs_odd) / 2.0

        # Avoid division by zero for pairs that never occur in this window
        valid = expected > 0
        if valid.sum() < 2:
            scores.append(0.0)
            continue

        chi2_stat = np.sum(((observed[valid] - expected[valid]) ** 2) / expected[valid])
        degrees_of_freedom = valid.sum() - 1
        p_value = 1.0 - stats.chi2.cdf(chi2_stat, degrees_of_freedom)
        scores.append(float(p_value))
    return scores


def analyze_image(image: Image.Image, window: int = 2000, step: int = 500) -> dict:
    """Run the chi-square attack across all three RGB channels of an
    image, flattened in the same raster order Arcanux embeds in."""
    rgb = np.array(image.convert("RGB"))
    flat = rgb.reshape(-1)  # interleaved R,G,B,R,G,B,... same order as embed_bytes

    scores = chi_square_lsb_scores(flat, window=window, step=step)
    return {
        "mean_p_value": float(np.mean(scores)) if scores else 0.0,
        "max_p_value": float(np.max(scores)) if scores else 0.0,
        "fraction_windows_above_0.9": float(np.mean(np.array(scores) > 0.9)) if scores else 0.0,
        "num_windows": len(scores),
    }


def _random_image(width, height, seed):
    """
    Generate a synthetic 'natural-like' image directly at full
    resolution: smooth analytic gradients (sinusoidal, varying per
    channel) plus Gaussian pixel noise. This produces the peaky,
    non-uniform, spatially-correlated histograms real photographs have.

    Two earlier approaches were tried and rejected, worth recording
    here so the choice isn't mysterious:

    1. Pure uniform random noise as baseline — rejected because a flat
       histogram already has near-equalized LSB-pair frequencies by
       construction, making the chi-square attack blind for the wrong
       reason (the image looked like noise before any embedding).

    2. Low-res noise upscaled with bicubic interpolation — rejected
       because resizing/interpolation is a KNOWN source of false
       positives for the chi-square attack: the interpolation itself
       perturbs LSB statistics in a way that mimics embedding, which
       made even the unembedded baseline score artificially high.

    This generator avoids both: no resize step, and the sinusoidal
    base gives real spatial structure without an artificial LSB
    signature.
    """
    rng = np.random.default_rng(seed)
    y, x = np.mgrid[0:height, 0:width]
    channels = []
    for _ in range(3):
        freq_x = rng.uniform(0.01, 0.05)
        freq_y = rng.uniform(0.01, 0.05)
        phase = rng.uniform(0, 6.28)
        base = 128 + 100 * np.sin(x * freq_x + phase) * np.cos(y * freq_y)
        noise = rng.normal(0, 8, (height, width))
        channel = np.clip(base + noise, 0, 255).astype(np.uint8)
        channels.append(channel)
    return Image.fromarray(np.stack(channels, axis=-1), "RGB")


def _low_noise_image(width, height, seed):
    """
    A smooth synthetic gradient with NO added noise — the classic image
    class the chi-square attack was originally designed against (this
    style resembles simple synthetic graphics / palette-based images
    more than photographic sensor output). Used here purely to sanity-
    check that the chi-square implementation itself is correct, by
    confirming it DOES show a clear signal when one is expected.
    """
    rng = np.random.default_rng(seed)
    y, x = np.mgrid[0:height, 0:width]
    freq_x, freq_y = rng.uniform(0.01, 0.05, 2)
    base = 128 + 100 * np.sin(x * freq_x) * np.cos(y * freq_y)
    channel = np.clip(base, 0, 255).astype(np.uint8)
    return Image.fromarray(np.stack([channel] * 3, axis=-1), "RGB")


def run_self_test():
    from src.stego.capacity import calculate_image_capacity_bytes
    results = {}

    # --- Part A: sanity-check the attack implementation itself -----
    # On a low-noise synthetic image, the chi-square attack should show
    # a CLEAR separation between clean and embedded. If it doesn't,
    # something is wrong with the attack code, not with Arcanux.
    low_noise = _low_noise_image(400, 400, seed=1)
    results["sanity_check__low_noise_clean"] = analyze_image(low_noise)
    cap_ln = calculate_image_capacity_bytes(low_noise)
    stego_ln = image_embed.embed_bytes(low_noise, os.urandom(cap_ln))
    results["sanity_check__low_noise_fully_embedded"] = analyze_image(stego_ln)

    # --- Part B: the realistic case Arcanux actually targets -----
    # Photographic-style images with sensor-like noise. This is the
    # honest measurement that goes in the threat model.
    clean = _random_image(400, 400, seed=1)
    results["photographic__clean_baseline"] = analyze_image(clean)

    full_capacity = calculate_image_capacity_bytes(clean)
    payload_full = os.urandom(full_capacity)
    stego_full = image_embed.embed_bytes(clean, payload_full)
    results["photographic__fully_embedded"] = analyze_image(stego_full)

    payload_partial = os.urandom(int(full_capacity * 0.2))
    stego_partial = image_embed.embed_bytes(clean, payload_partial)
    results["photographic__partially_embedded_20pct"] = analyze_image(stego_partial)

    payload_light = os.urandom(int(full_capacity * 0.02))
    stego_light = image_embed.embed_bytes(clean, payload_light)
    results["photographic__lightly_embedded_2pct"] = analyze_image(stego_light)

    return results


if __name__ == "__main__":
    results = run_self_test()
    print(f"{'Scenario':<40} {'mean p':>8} {'max p':>8} {'%windows>0.9':>14} {'windows':>8}")
    for name, r in results.items():
        print(f"{name:<40} {r['mean_p_value']:>8.3f} {r['max_p_value']:>8.3f} "
              f"{r['fraction_windows_above_0.9']*100:>13.1f}% {r['num_windows']:>8}")

    print()
    print("Interpretation:")
    print("- sanity_check rows should show LOW p on clean, HIGH p on embedded.")
    print("  This confirms the attack implementation itself is working correctly.")
    print("- photographic rows are the realistic case. If clean and embedded")
    print("  scores are close together there, it means photographic sensor")
    print("  noise already randomizes the LSB plane enough to blunt this")
    print("  particular attack — a real, documented property of the chi-square")
    print("  attack, not a Arcanux-specific claim of undetectability.")
