"""Local Ed25519 signing identity.

On first use, the library creates a per-user signing identity under ``~/.guardrail_evidence``
(override with the ``GUARDRAIL_EVIDENCE_HOME`` environment variable):

* ``signing_key.pem``  — Ed25519 private key, PKCS#8 PEM, mode ``0600``
* ``verify_key.pem``   — Ed25519 public key, SubjectPublicKeyInfo PEM

The directory is created with mode ``0700`` where the platform supports it.
No shared or default key is ever embedded; private-key material is never
printed and never included in events.

``key_id`` is derived from the public key: ``ed25519:`` followed by the first
16 hex characters of the SHA-256 of the raw 32-byte public key. The full
SHA-256 hex is exposed as the *fingerprint* via ``guardrail-evidence key-info``.

Signature scheme (matching the guard runtime receipt convention): the signer
computes ``digest = SHA-256(canonical_unsigned_payload_bytes)`` and produces
``Ed25519.sign(digest)``, base64-encoded. Verification recomputes the digest
and verifies the signature against it.
"""

from __future__ import annotations

import base64
import os
import stat
from pathlib import Path
from typing import Protocol

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from .canonical import sha256_hex
from .errors import IdentityError, SigningError

PRIVATE_KEY_FILENAME = "signing_key.pem"
PUBLIC_KEY_FILENAME = "verify_key.pem"
JOURNAL_FILENAME = "journal.jsonl"


def evidence_home() -> Path:
    """The evidence home directory (``GUARDRAIL_EVIDENCE_HOME`` or ``~/.guardrail-evidence``)."""
    override = os.environ.get("GUARDRAIL_EVIDENCE_HOME")
    if override:
        return Path(override).expanduser()
    return Path.home() / ".guardrail_evidence"


def default_journal_path() -> Path:
    return evidence_home() / JOURNAL_FILENAME


class SigningIdentity(Protocol):
    """What the guard needs from an identity; an observer integration can supply
    another implementation (e.g. a managed key) without touching guard code."""

    @property
    def key_id(self) -> str: ...

    def sign(self, digest: bytes) -> str:
        """Base64 Ed25519 signature over *digest* bytes."""
        ...


class LocalSigningIdentity:
    """File-backed Ed25519 identity in the evidence home directory."""

    def __init__(self, private_key: Ed25519PrivateKey, home: Path) -> None:
        self._private_key = private_key
        self._home = home
        self._public_raw = private_key.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )

    @classmethod
    def load_or_create(cls, home: Path | None = None) -> LocalSigningIdentity:
        home = home or evidence_home()
        private_path = home / PRIVATE_KEY_FILENAME
        public_path = home / PUBLIC_KEY_FILENAME
        try:
            if private_path.exists():
                _require_private_permissions(private_path)
                private_key = _load_private_key(private_path)
            else:
                home.mkdir(parents=True, exist_ok=True)
                _restrict_dir(home)
                private_key = Ed25519PrivateKey.generate()
                _write_private_key(private_path, private_key)
                _write_public_key(public_path, private_key.public_key())
            # Self-heal a missing public key file (it is derivable).
            if not public_path.exists():
                _write_public_key(public_path, private_key.public_key())
        except OSError as exc:
            raise IdentityError(f"cannot create or load signing identity in {home}: {exc}") from exc
        return cls(private_key, home)

    @property
    def home(self) -> Path:
        return self._home

    @property
    def public_key_path(self) -> Path:
        return self._home / PUBLIC_KEY_FILENAME

    @property
    def fingerprint(self) -> str:
        """Full SHA-256 hex of the raw 32-byte public key."""
        return sha256_hex(self._public_raw)

    @property
    def key_id(self) -> str:
        return f"ed25519:{self.fingerprint[:16]}"

    def sign(self, digest: bytes) -> str:
        try:
            signature = self._private_key.sign(digest)
        except Exception as exc:  # cryptography raises library-specific errors
            raise SigningError(f"Ed25519 signing failed: {exc}") from exc
        return base64.b64encode(signature).decode("ascii")

    def public_key(self) -> Ed25519PublicKey:
        return self._private_key.public_key()


def load_public_key(path: Path) -> Ed25519PublicKey:
    try:
        key = serialization.load_pem_public_key(path.read_bytes())
    except (OSError, ValueError) as exc:
        raise IdentityError(f"cannot load public key from {path}: {exc}") from exc
    if not isinstance(key, Ed25519PublicKey):
        raise IdentityError(f"{path} is not an Ed25519 public key")
    return key


def public_key_fingerprint(key: Ed25519PublicKey) -> str:
    raw = key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return sha256_hex(raw)


def key_id_for(key: Ed25519PublicKey) -> str:
    return f"ed25519:{public_key_fingerprint(key)[:16]}"


def verify_signature(key: Ed25519PublicKey, digest: bytes, signature_b64: str) -> bool:
    try:
        signature = base64.b64decode(signature_b64, validate=True)
    except Exception:
        return False
    try:
        key.verify(signature, digest)
        return True
    except InvalidSignature:
        return False


def _require_private_permissions(path: Path) -> None:
    """Refuse to sign with a private key other local users can read.

    Creating the key restricts it to ``0600``, but that says nothing about the
    key as found on a later run. Keys get copied between machines, restored
    from backups that flatten permissions, committed to a repository, or
    written into a container image with a permissive umask. Signing with a
    readable key produces evidence that looks exactly as authoritative as
    evidence signed with a protected one, which is the problem: the signature
    attests to a key anyone on the host could have used.

    Skipped where POSIX permission bits are not meaningful.
    """
    if os.name != "posix":
        return
    try:
        mode = path.stat().st_mode
    except OSError:
        return
    if mode & (stat.S_IRWXG | stat.S_IRWXO):
        raise IdentityError(
            f"private key {path} is accessible to other users "
            f"(mode {stat.filemode(mode)}); refusing to sign with it. "
            f"Fix with: chmod 600 {path}"
        )


def _load_private_key(path: Path) -> Ed25519PrivateKey:
    try:
        key = serialization.load_pem_private_key(path.read_bytes(), password=None)
    except (OSError, ValueError, TypeError) as exc:
        raise IdentityError(f"cannot load private key from {path}: {exc}") from exc
    if not isinstance(key, Ed25519PrivateKey):
        raise IdentityError(f"{path} is not an Ed25519 private key")
    return key


def _write_private_key(path: Path, key: Ed25519PrivateKey) -> None:
    pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    _write_restricted(path, pem, stat.S_IRUSR | stat.S_IWUSR)


def _write_public_key(path: Path, key: Ed25519PublicKey) -> None:
    pem = key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    path.write_bytes(pem)


def _write_restricted(path: Path, data: bytes, mode: int) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC
    try:
        fd = os.open(path, flags, mode)
    except OSError as exc:
        raise IdentityError(f"cannot write {path}: {exc}") from exc
    try:
        os.write(fd, data)
    finally:
        os.close(fd)
    try:
        os.chmod(path, mode)
    except OSError:
        pass  # best-effort on platforms without POSIX permissions


def _restrict_dir(path: Path) -> None:
    try:
        os.chmod(path, stat.S_IRWXU)
    except OSError:
        pass  # best-effort on platforms without POSIX permissions
