"""Unit: Shannon entropy vectors, encoding guesses, thresholds, margins."""

import math

from secretsieve.detectors import entropy as ent


def test_shannon_known_vectors():
    assert ent.shannon("") == 0.0
    assert ent.shannon("aaaa") == 0.0
    assert ent.shannon("ab") == 1.0
    # 4 equally likely symbols -> 2 bits/char.
    assert ent.shannon("aabbccdd") == 2.0
    # Uniform 64-symbol alphabet -> 6 bits/char.
    import string

    alphabet = string.ascii_letters + string.digits + "+/"
    assert abs(ent.shannon(alphabet) - 6.0) < 1e-9


def test_char_classes_and_variety():
    assert ent.char_classes("abc") == {"lower"}
    assert ent.char_classes("aB1!") == {"lower", "upper", "digit", "symbol"}
    assert not ent.has_enough_variety("aaaaaaaaaaaaaaaa")
    assert not ent.has_enough_variety("1111111111111111")
    assert ent.has_enough_variety("Ab3x9QwE7kLmN2pR5sT8uV")
    # Long single-class hex-ish strings are still analyzable.
    assert ent.has_enough_variety("9f8e7d6c5b4a3928174656f7a8b")


def test_guess_encoding():
    assert ent.guess_encoding("9f8e7d6c5b4a3928174656f7a8b9c0d1e2f3") == "hex"
    assert ent.guess_encoding("9f8e7d6c5b4a3928174656f7a8b9c0d1e2f3a4b5c6d7e8f+OE=") in ("base64", "other")
    assert ent.guess_encoding("hello world secret") == "other"
    assert ent.guess_encoding("eyJhbGciOiJIUzI1NiJ9") in ("base64url", "base64", "other")


def test_threshold_modifiers():
    base = ent.effective_threshold("base64", base64_threshold=4.5, hex_threshold=3.7, mixed_threshold=4.0)
    strong = ent.effective_threshold("base64", base64_threshold=4.5, hex_threshold=3.7, mixed_threshold=4.0, strong_context=True)
    benign = ent.effective_threshold("base64", base64_threshold=4.5, hex_threshold=3.7, mixed_threshold=4.0, benign_context=True)
    gen = ent.effective_threshold("base64", base64_threshold=4.5, hex_threshold=3.7, mixed_threshold=4.0, generated=True)
    assert strong == base - 0.4
    assert benign == base + 0.5
    assert gen == base + 0.5


def test_bonus_ladder():
    assert ent.entropy_bonus(-0.1) == 0
    assert ent.entropy_bonus(0.0) == 5
    assert ent.entropy_bonus(0.49) == 5
    assert ent.entropy_bonus(0.5) == 10
    assert ent.entropy_bonus(0.99) == 10
    assert ent.entropy_bonus(1.0) == 15


def test_analyze_gates():
    short = ent.analyze("abc", "mixed")
    assert not short.passed
    low = ent.analyze("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "mixed")
    assert not low.passed  # no variety
    good = ent.analyze("9f8e7d6c5b4a3928174656f7a8b9c0d1e2f3a4b5c6d", "mixed", strong_context=True)
    assert good.passed and good.bonus >= 5


def test_entropy_never_fires_alone_by_contract():
    # EntropyResult carries no finding semantics: the engine must combine it
    # with context. This test pins the type contract (no Finding here).
    res = ent.analyze("9f8e7d6c5b4a3928174656f7a8b9c0d1e2f3a4b5c6d", "mixed", strong_context=True)
    assert isinstance(res.margin, float) and isinstance(res.passed, bool)
