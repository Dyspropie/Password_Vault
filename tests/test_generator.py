"""Unit tests for password generation and strength scoring."""

from __future__ import annotations

import pytest

from vault.errors import GeneratorError
from vault.generator import LOOKALIKE_CHARS, entropy_bits, generate_password
from vault.strength import calculate_strength


def test_generator_length_bounds() -> None:
    """Verify password length boundaries and exceptions."""
    for length in (8, 12, 20, 32, 64):
        pwd = generate_password(length=length)
        assert len(pwd) == length

    with pytest.raises(GeneratorError):
        generate_password(length=7)

    with pytest.raises(GeneratorError):
        generate_password(length=65)


def test_each_set_guaranteed_present() -> None:
    """Verify that at least one character from each selected set is guaranteed."""
    for _ in range(50):
        pwd = generate_password(
            length=12,
            use_lower=True,
            use_upper=True,
            use_digits=True,
            use_symbols=True,
        )
        assert any(c.islower() for c in pwd)
        assert any(c.isupper() for c in pwd)
        assert any(c.isdigit() for c in pwd)
        assert any(not c.isalnum() for c in pwd)


def test_excluded_lookalike_characters_absent() -> None:
    """Verify that look-alike characters (0, O, o, 1, l, I) are completely absent when excluded."""
    for _ in range(50):
        pwd = generate_password(
            length=32,
            exclude_lookalikes=True,
        )
        for char in LOOKALIKE_CHARS:
            assert char not in pwd


def test_empty_character_selection_raises() -> None:
    """Verify that selecting no character sets raises GeneratorError."""
    with pytest.raises(GeneratorError):
        generate_password(
            use_lower=False,
            use_upper=False,
            use_digits=False,
            use_symbols=False,
        )


def test_ten_thousand_passwords_no_duplicates() -> None:
    """Verify that generating 10,000 passwords produces zero collisions."""
    generated = {generate_password(length=20) for _ in range(10000)}
    assert len(generated) == 10000


def test_entropy_calculation() -> None:
    """Verify entropy calculation helper."""
    assert entropy_bits(0, 50) == 0.0
    assert entropy_bits(20, 0) == 0.0
    # 20 chars from pool of 64 characters -> 20 * log2(64) = 120.0 bits
    assert entropy_bits(20, 64) == 120.0


def test_strength_score_ordering() -> None:
    """Verify that password strength scoring is monotonic and orders passwords logically."""
    very_weak = calculate_strength("password")
    weak = calculate_strength("shorty1")
    fair = calculate_strength("ModerateP@ss")
    good = calculate_strength("GoodStrongPass123!")
    strong = calculate_strength("ExtremelyStrong_ComplexPassphrase_999#$")

    assert very_weak.score == 0
    assert very_weak.label == "Very weak"

    assert very_weak.score <= weak.score <= fair.score <= good.score <= strong.score
    assert strong.score == 4
    assert strong.label == "Strong"
