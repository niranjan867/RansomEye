"""Entropy analysis utility for RansomEye.

Calculates Shannon entropy of data buffers and files. Used to identify
obfuscated, packed, or encrypted content (such as ransomware payloads).

Adapted from:
    12X-RANSOMWARE-ANALYSIS/NEXUS-SCAN/nexus_scan/analysis/entropy.py
"""

from __future__ import annotations

import math
import os
from typing import Sequence


class EntropyAnalyzer:
    """Calculates Shannon entropy for detecting obfuscated/packed content.

    Shannon entropy ranges:
      0.0 - 1.0 : Nearly all same bytes (e.g. null padding)
      4.0 - 6.0 : Normal executable code/text
      6.5 - 7.0 : Compressed data
      7.0 - 8.0 : Encrypted / packed content (suspicious)
    """

    def calculate(self, data: bytes) -> float:
        """Calculate Shannon entropy of a byte sequence. Returns 0.0 - 8.0."""
        if not data:
            return 0.0

        freq = [0] * 256
        for byte in data:
            freq[byte] += 1

        length = len(data)
        entropy = 0.0
        for count in freq:
            if count > 0:
                p = count / length
                entropy -= p * math.log2(p)

        return round(entropy, 4)

    def calculate_chunks(self, data: bytes, chunk_size: int = 256) -> list[float]:
        """Calculate entropy across chunks of data.

        Useful for visualizing entropy distribution in a file.
        """
        if chunk_size <= 0:
            raise ValueError("chunk_size must be positive")
        
        chunks = []
        for i in range(0, len(data), chunk_size):
            chunk = data[i:i + chunk_size]
            chunks.append(self.calculate(chunk))
        return chunks

    def is_packed(self, data: bytes, threshold: float = 7.0) -> bool:
        """Return True if the data is likely packed or encrypted."""
        return self.calculate(data) >= threshold

    def get_entropy_rating(self, entropy: float) -> str:
        """Return human-readable rating of entropy score."""
        if entropy < 1.0:
            return "Very Low (null padding)"
        elif entropy < 4.0:
            return "Low (plaintext)"
        elif entropy < 6.5:
            return "Normal (compiled code)"
        elif entropy < 7.0:
            return "High (possibly compressed)"
        else:
            return "Very High (likely packed/encrypted)"


def calculate_file_entropy(path: str) -> float:
    """Read file bytes and calculate its Shannon entropy.

    Returns 0.0 if file is empty or cannot be read.
    """
    if not path or not os.path.exists(path) or os.path.isdir(path):
        return 0.0
    try:
        with open(path, "rb") as fh:
            data = fh.read()
        analyzer = EntropyAnalyzer()
        return analyzer.calculate(data)
    except Exception:
        return 0.0
