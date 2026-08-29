"""Unit tests for ransomeye.entropy.

Verifies deterministic Shannon entropy calculation, ratings, chunking, and file
access wrappers.
"""

from __future__ import annotations

import math
import os
import sys
from typing import Any

import pytest

# Allow running with `python -m pytest tests/` when the package is not installed.
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from ransomeye.entropy import EntropyAnalyzer, calculate_file_entropy


class TestEntropyAnalyzer:

    def test_empty_buffer_returns_zero(self) -> None:
        analyzer = EntropyAnalyzer()
        assert analyzer.calculate(b"") == 0.0

    def test_single_repeated_byte_has_zero_entropy(self) -> None:
        analyzer = EntropyAnalyzer()
        data = b"A" * 100
        assert analyzer.calculate(data) == 0.0

    def test_uniform_distribution_has_max_entropy(self) -> None:
        analyzer = EntropyAnalyzer()
        # 256 unique bytes
        data = bytes(range(256))
        # Log2(256) = 8.0
        assert analyzer.calculate(data) == 8.0

    def test_is_packed_threshold(self) -> None:
        analyzer = EntropyAnalyzer()
        # Plain text
        plain = b"This is a standard text buffer with low entropy."
        assert analyzer.is_packed(plain) is False

        # Random bytes (simulated high entropy)
        high_entropy = bytes(range(256)) * 4
        assert analyzer.is_packed(high_entropy, threshold=7.5) is True

    def test_get_entropy_rating(self) -> None:
        analyzer = EntropyAnalyzer()
        assert "Very Low" in analyzer.get_entropy_rating(0.5)
        assert "Low" in analyzer.get_entropy_rating(3.0)
        assert "Normal" in analyzer.get_entropy_rating(5.5)
        assert "High" in analyzer.get_entropy_rating(6.8)
        assert "Very High" in analyzer.get_entropy_rating(7.6)

    def test_calculate_chunks(self) -> None:
        analyzer = EntropyAnalyzer()
        data = b"A" * 256 + b"B" * 256
        chunks = analyzer.calculate_chunks(data, chunk_size=256)
        assert len(chunks) == 2
        assert chunks[0] == 0.0
        assert chunks[1] == 0.0

        with pytest.raises(ValueError):
            analyzer.calculate_chunks(data, chunk_size=0)

    def test_calculate_file_entropy_missing(self) -> None:
        assert calculate_file_entropy("") == 0.0
        assert calculate_file_entropy("nonexistent_path.bin") == 0.0

    def test_calculate_file_entropy_success(self, tmp_path: Any) -> None:
        p = tmp_path / "test.dat"
        p.write_bytes(bytes(range(256)))
        assert calculate_file_entropy(str(p)) == 8.0
