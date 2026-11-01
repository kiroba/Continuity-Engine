"""
DEPRECATED: zero-dependency social import engine.

This module used to sign profile events with HMAC-SHA256 over a secret, which no
peer could verify (verifying an HMAC needs the secret). Profile events are now
signed with real Ed25519 keys in the canonical Omni-Daemon event format, and that
needs the `cryptography` package, so a "zero-dependency" variant no longer has a
reason to exist. Use `continuity_social_import_engine` directly:

    from continuity_social_import_engine import ContinuitySocialImportEngine

This shim keeps old imports working. It delegates everything to the Ed25519
engine and emits a DeprecationWarning. It will be removed in a later release.

pip install cryptography
"""

from dataclasses import dataclass
import secrets
import warnings
from typing import Optional

try:  # imported as part of a package
    from .continuity_social_import_engine import (
        ContinuitySocialImportEngine as _Ed25519Engine,
        ed25519,
        pubkey_hex as _pubkey_hex,
        verify_event,
    )
except ImportError:  # run as a script / imported with integrations/ on sys.path
    from continuity_social_import_engine import (
        ContinuitySocialImportEngine as _Ed25519Engine,
        ed25519,
        pubkey_hex as _pubkey_hex,
        verify_event,
    )

__all__ = ["ContinuitySocialImportEngine", "ZeroDepKey", "verify_event"]

warnings.warn(
    "zero_dep_continuity_social_import_engine is deprecated; import "
    "continuity_social_import_engine instead (events are now Ed25519-signed).",
    DeprecationWarning,
    stacklevel=2,
)


@dataclass
class ZeroDepKey:
    """Deprecated key container. secret_key is now a 32-byte Ed25519 private key seed
    and pubkey_hex is its real 64-hex Ed25519 public key."""
    secret_key: bytes
    pubkey_hex: str

    @classmethod
    def generate(cls) -> "ZeroDepKey":
        return cls.from_secret(secrets.token_bytes(32))

    @classmethod
    def from_secret(cls, secret_key: bytes) -> "ZeroDepKey":
        priv = ed25519.Ed25519PrivateKey.from_private_bytes(secret_key)
        return cls(secret_key=secret_key, pubkey_hex=_pubkey_hex(priv))

    def private_key(self) -> ed25519.Ed25519PrivateKey:
        return ed25519.Ed25519PrivateKey.from_private_bytes(self.secret_key)


class ContinuitySocialImportEngine(_Ed25519Engine):
    """Deprecated: accepts the old key_pair= argument and signs with Ed25519."""

    def __init__(self, key_pair: Optional[ZeroDepKey] = None,
                 private_key: Optional[ed25519.Ed25519PrivateKey] = None):
        if key_pair is not None and private_key is not None:
            raise ValueError("pass key_pair or private_key, not both")
        if key_pair is not None:
            private_key = key_pair.private_key()
        super().__init__(private_key)
        self.key_pair = key_pair


if __name__ == "__main__":
    print("zero_dep_continuity_social_import_engine is deprecated; running the Ed25519 engine.")
    engine = ContinuitySocialImportEngine(ZeroDepKey.generate())
    event = engine.import_external_profile(
        platform_name="X_TWITTER",
        external_handle="@alice_creator",
        bio="Digital artist & game builder in Omniverse",
        contacts_raw=[{"name": "Bob Smith", "email": "bob@example.com"}],
    )
    assert verify_event(event), "Ed25519 signature failed to verify"
    print(f"[✓] Event {event['event_id'][:18]}... verifies against {event['author_pubkey'][:16]}...")
