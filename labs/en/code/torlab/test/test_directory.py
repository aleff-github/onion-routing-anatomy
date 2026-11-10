# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Alessandro Greco
"""Laboratory 6 tests using a real consensus from the private laboratory network (saved under data/)."""
from pathlib import Path
import hashlib
from types import SimpleNamespace
import pytest

from torlab.directory import parse_certificates, parse_consensus, items, verify_consensus

DATA = Path(__file__).parent / "data"
TEXT = (DATA / "consensus-microdesc.txt").read_text()
CERTS = parse_certificates((DATA / "authority-certificates.txt").read_text())


def test_structure():
    c = parse_consensus(TEXT)
    assert c.header["network-status-version"] == ["3", "microdesc"]
    assert len(c.relay) == 8 and len(c.signatures) == 3
    assert sum("Exit" in r.flag for r in c.relay) == 2
    assert all(len(r.microdesc) == 32 for r in c.relay)


def test_valid_signatures():
    valid_count, required, _ = verify_consensus(parse_consensus(TEXT), CERTS, 3)
    assert (valid_count, required) == (3, 2)


def test_modified_consensus():
    tampered = TEXT.replace("Bandwidth=4096", "Bandwidth=4097", 1)
    assert verify_consensus(parse_consensus(tampered), CERTS, 3)[0] == 0


def test_unknown_authority_signature():
    only_one = [CERTS[0]]
    assert verify_consensus(parse_consensus(TEXT), only_one, 3)[0] == 1


def test_items_with_objects():
    it = items("a 1 2\nb\n-----BEGIN X-----\nQUJD\n-----END X-----\nc\n")
    assert [i.keyword for i in it] == ["a", "b", "c"]
    assert it[1].object_text.startswith(b"-----BEGIN X-----")


def test_signed_text_ignores_collector_annotation():
    """CollecTor files may begin with "@type ..."; that annotation is not part of the signed text."""
    from torlab.directory import signed_text
    assert signed_text("@type network-status-microdesc-consensus-3 1.0\n" + TEXT) == signed_text(TEXT)

def test_unterminated_pem_rejected():
    # The parser must not run past the end of the document.
    with pytest.raises(ValueError):
        items("x\n-----BEGIN TEST-----\nQUJD\n")
    with pytest.raises(ValueError):
        items("x\n-----BEGIN TEST-----\nQUJD\n-----END OTHER-----\n")


def test_unknown_signature_algorithm_is_not_sha1():
    from torlab.directory import parse_consensus, verify_signature, Signature, signed_text
    parsed = parse_consensus(TEXT)
    digest = hashlib.sha1(signed_text(parsed.text)).digest()
    fake_cert = SimpleNamespace(signing_key=SimpleNamespace(
        recover_data_from_signature=lambda *args: digest))
    unknown = Signature("sha999", "00", "11", b"signature")
    assert verify_signature(parsed, unknown, fake_cert) is False


def test_microdescriptor_collector_annotations_do_not_enter_digest():
    from torlab.directory import parse_microdescriptors
    first = "onion-key\nntor-onion-key QUJD\n"
    second = "onion-key\nntor-onion-key QUJE\n"
    annotated = first + "@last-listed 2026-09-23 16:00:00\n" + second
    parsed = parse_microdescriptors(annotated)
    assert hashlib.sha256(first.encode()).digest() in parsed
    assert hashlib.sha256(second.encode()).digest() in parsed
    assert len(parsed) == 2
