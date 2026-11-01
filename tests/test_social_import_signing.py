"""Ed25519 signing tests for the social import engine and its deprecated zero-dep shim.

Run from the repo root: python3 -m unittest   (needs: pip install cryptography)
"""
import copy
import hashlib
import json
import os
import sys
import tempfile
import unittest
import warnings
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "integrations"))

from cryptography.exceptions import InvalidSignature  # noqa: E402
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey  # noqa: E402

import continuity_social_import_engine as ed  # noqa: E402

with warnings.catch_warnings(record=True) as _caught:
    warnings.simplefilter("always")
    import zero_dep_continuity_social_import_engine as lite  # noqa: E402
SHIM_WARNINGS = [w for w in _caught if issubclass(w.category, DeprecationWarning)]

CONTACTS = [
    {"name": "Bob Smith", "email": "bob@example.com"},
    {"name": "Carol Danvers", "phone": "+15551234567"},
]


def daemon_canonical_bytes(event):
    """Independent copy of Omni-Daemon Admin/omni_signing.canonical_event_bytes (int-ms 'ts' form)."""
    struct = {k: event[k] for k in ("action", "author_pubkey", "payload", "previous_hash", "ts")}
    return json.dumps(struct, sort_keys=True, separators=(",", ":")).encode("utf-8")


def verify_with_public_key(event):
    pub = Ed25519PublicKey.from_public_bytes(bytes.fromhex(event["author_pubkey"]))
    pub.verify(bytes.fromhex(event["signature"]), daemon_canonical_bytes(event))  # raises if tampered


def make_event(engine):
    return engine.import_external_profile("X_TWITTER", "@alice", "bio", CONTACTS)


class LitePathSigningTest(unittest.TestCase):
    def setUp(self):
        self.key = lite.ZeroDepKey.generate()
        self.engine = lite.ContinuitySocialImportEngine(self.key)
        self.event = make_event(self.engine)

    def test_shim_warns_deprecated(self):
        self.assertTrue(SHIM_WARNINGS, "importing the zero-dep module should warn")

    def test_lite_event_verifies_with_ed25519_public_key(self):
        self.assertEqual(self.event["author_pubkey"], self.key.pubkey_hex)
        self.assertEqual(len(self.event["author_pubkey"]), 64)
        self.assertEqual(len(self.event["signature"]), 128)
        verify_with_public_key(self.event)  # no exception = valid
        self.assertTrue(ed.verify_event(self.event))

    def test_tampered_payload_fails(self):
        bad = copy.deepcopy(self.event)
        bad["payload"]["imported_bio"] = "tampered"
        with self.assertRaises(InvalidSignature):
            verify_with_public_key(bad)
        self.assertFalse(ed.verify_event(bad))

    def test_tampered_envelope_fields_fail(self):
        for field, value in (("ts", self.event["ts"] + 1),
                             ("previous_hash", "0x" + "1" * 64),
                             ("action", "SOMETHING_ELSE")):
            bad = dict(self.event, **{field: value})
            self.assertFalse(ed.verify_event(bad), field)

    def test_wrong_author_key_fails(self):
        other = lite.ZeroDepKey.generate()
        self.assertFalse(ed.verify_event(dict(self.event, author_pubkey=other.pubkey_hex)))

    def test_same_seed_same_key_as_main_engine(self):
        main = ed.ContinuitySocialImportEngine(self.key.private_key())
        self.assertEqual(main.pubkey_hex, self.engine.pubkey_hex)


class CanonicalFormatTest(unittest.TestCase):
    def setUp(self):
        self.engine = ed.ContinuitySocialImportEngine()
        self.event = make_event(self.engine)

    def test_envelope_is_daemon_user_event(self):
        self.assertEqual(set(self.event), {"event_id", "action", "author_pubkey", "previous_hash",
                                           "ts", "payload", "signature"})
        self.assertEqual(self.event["action"], "PROFILE_SOCIAL_IMPORT")
        self.assertIsInstance(self.event["ts"], int)
        self.assertEqual(self.event["previous_hash"], "0x" + "0" * 64)

    def test_event_id_is_sha256_of_canonical_bytes(self):
        expected = "0x" + hashlib.sha256(daemon_canonical_bytes(self.event)).hexdigest()
        self.assertEqual(self.event["event_id"], expected)
        self.assertEqual(ed.canonical_event_bytes(self.event), daemon_canonical_bytes(self.event))

    def test_chaining_uses_previous_event_id(self):
        nxt = self.engine.import_external_profile("X_TWITTER", "@alice", "bio2", CONTACTS,
                                                  prev_hash=self.event["event_id"])
        self.assertEqual(nxt["previous_hash"], self.event["event_id"])
        self.assertTrue(ed.verify_event(nxt))

    def test_bare_hex_prev_hash_gets_prefix_and_bad_one_rejected(self):
        ev = self.engine.import_external_profile("X", "@a", "b", [], prev_hash="ab" * 32)
        self.assertEqual(ev["previous_hash"], "0x" + "ab" * 32)
        with self.assertRaises(ValueError):
            self.engine.import_external_profile("X", "@a", "b", [], prev_hash="not-a-hash")


class KeyFileTest(unittest.TestCase):
    def test_key_file_is_persistent_raw_and_private(self):
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / "sub" / "node_ed25519.key"
            first = ed.ContinuitySocialImportEngine.from_key_file(path)
            second = ed.ContinuitySocialImportEngine.from_key_file(path)
            self.assertEqual(first.pubkey_hex, second.pubkey_hex)
            self.assertEqual(len(path.read_bytes()), 32)
            if os.name == "posix":
                self.assertEqual(path.stat().st_mode & 0o777, 0o600)


if __name__ == "__main__":
    unittest.main()
