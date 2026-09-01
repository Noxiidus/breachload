"""Generalized app-config secret extraction library."""

import base64
import hashlib
import json

import pytest

from breachload.analysis.app_secrets import (
    decrypt,
    decrypt_nifi,
    discovery_commands,
    find_encrypted_values,
    profile,
    profiles_for_state,
)
from breachload.core.state import EngagementState, Service

# cryptography is optional; skip decrypt round-trips when it isn't installed.
try:
    import cryptography  # noqa: F401
    _HAVE_CRYPTO = True
except Exception:
    _HAVE_CRYPTO = False
requires_crypto = pytest.mark.skipif(not _HAVE_CRYPTO,
                                     reason="cryptography not installed")


class TestProfileLookup:
    def test_known_apps(self):
        for app in ("nifi", "laravel", "django", "wordpress", "jenkins", "gitlab"):
            assert profile(app) is not None

    def test_case_insensitive_partial(self):
        assert profile("NiFi") is not None
        assert profile("Apache NiFi 1.21") is not None

    def test_unknown(self):
        assert profile("totally-unknown-app") is None

    def test_none(self):
        assert profile("") is None


class TestDiscoveryCommands:
    def test_nifi_shows_flow_and_key_paths(self):
        cmds = "\n".join(discovery_commands(profile("nifi")))
        assert "flow.json.gz" in cmds and "nifi.properties" in cmds
        # zgrep should appear for .gz configs
        assert "zgrep" in cmds

    def test_laravel_env(self):
        cmds = "\n".join(discovery_commands(profile("laravel")))
        assert ".env" in cmds and "APP_KEY" in cmds

    def test_all_profiles_produce_commands(self):
        from breachload.analysis.app_secrets import _PROFILES
        for k, p in _PROFILES.items():
            assert discovery_commands(p), f"empty commands for {k}"


class TestProfilesForState:
    def test_matches_by_note(self):
        st = EngagementState(name="t")
        h = st.upsert_host("10.10.10.5")
        h.upsert_service(Service(port=80, name="http", notes=["webapp: Apache NiFi 1.21"]))
        found = profiles_for_state(st)
        assert any(p.app == "Apache NiFi" for p in found)


class TestFindEncryptedValues:
    def test_nifi_enc_block(self):
        text = 'Password":"enc{43191045764af67c90c816}"'
        hits = find_encrypted_values(text)
        assert any(h.startswith("enc{") for h in hits)

    def test_jasypt_enc(self):
        assert find_encrypted_values("db.password=ENC(YWJjZGVmZ2hpams=)")

    def test_dedup(self):
        h = find_encrypted_values("enc{abcd12345678} enc{abcd12345678}")
        assert len(h) == 1


@requires_crypto
class TestNifiDecrypt:
    def _encrypt(self, plaintext: str, key: str) -> str:
        """Encrypt with the SAME scheme decrypt_nifi expects (round-trip)."""
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        salt = bytes.fromhex("4e694669205374617469632053616c74")
        derived = hashlib.pbkdf2_hmac("sha512", key.encode(), salt, 160000, dklen=32)
        iv = b"\x00" * 12
        ct = AESGCM(derived).encrypt(iv, plaintext.encode(), None)
        return (iv + ct).hex()

    def test_roundtrip(self):
        key = "TUHh+YHA30zmdlcA8xq/elNBLPkO03Nl"
        blob = self._encrypt("Winter2025!", key)
        assert decrypt_nifi(blob, key) == "Winter2025!"
        # also via the dispatch function
        assert decrypt("nifi", blob, key) == "Winter2025!"

    def test_wrong_key(self):
        blob = self._encrypt("secret", "correct-key")
        assert decrypt_nifi(blob, "wrong-key") is None

    def test_malformed(self):
        assert decrypt_nifi("not-hex", "k") is None
        assert decrypt_nifi("", "k") is None


@requires_crypto
class TestLaravelDecrypt:
    def test_roundtrip(self):
        import hmac

        from cryptography.hazmat.primitives.ciphers import (
            Cipher,
            algorithms,
            modes,
        )
        # Encrypt exactly the way Laravel does, then decrypt via the module.
        key_b = b"\x11" * 32
        app_key = "base64:" + base64.b64encode(key_b).decode()
        iv_b = b"\x22" * 16
        plaintext = b"laravel-secret"
        # PKCS7 pad
        pad = 16 - (len(plaintext) % 16)
        padded = plaintext + bytes([pad]) * pad
        enc = Cipher(algorithms.AES(key_b), modes.CBC(iv_b)).encryptor()
        value = enc.update(padded) + enc.finalize()
        iv_b64 = base64.b64encode(iv_b).decode()
        val_b64 = base64.b64encode(value).decode()
        mac = hmac.new(key_b, (iv_b64 + val_b64).encode(), hashlib.sha256).hexdigest()
        payload = base64.b64encode(json.dumps(
            {"iv": iv_b64, "value": val_b64, "mac": mac}).encode()).decode()
        assert decrypt("laravel", payload, app_key) == "laravel-secret"


class TestDispatch:
    def test_unknown_app_returns_none(self):
        assert decrypt("nope", "abc", "k") is None

    def test_app_without_decoder_returns_none(self):
        # 'wordpress' has no built-in decoder scheme
        assert decrypt("wordpress", "x", "k") is None
