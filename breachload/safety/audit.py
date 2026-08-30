"""Append-only, tamper-evident audit log.

Every proposed action, safety decision, and execution is written here as a JSON
line. This is both the compliance trail and the raw material for the report.
Never truncated, never rewritten.

Each record carries a ``hash`` = SHA-256 over the record's content plus the
previous record's hash — a hash chain. Editing or deleting any past line breaks
every subsequent hash, so ``verify_chain`` can prove the log was not tampered with
after the fact. This is a genuine integrity guarantee for the evidence trail (it
detects tampering; it is not a signature — it does not prove *who* wrote it).
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

_GENESIS = "0" * 64


def _record_hash(record: dict, prev_hash: str) -> str:
    """SHA-256 over the record (minus its own hash) chained to the previous hash."""
    payload = {k: v for k, v in record.items() if k != "hash"}
    blob = json.dumps(payload, default=str, sort_keys=True)
    return hashlib.sha256((prev_hash + blob).encode("utf-8")).hexdigest()


class AuditLog:
    def __init__(self, path: Path) -> None:
        self.path = path
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._tip: str | None = None      # cached hash of the last written record

    def _last_hash(self) -> str:
        """The hash of the final existing record, or the genesis hash.

        Cached after the first read so a long engagement doesn't re-scan the whole
        log on every write (O(n) per write -> O(1) after warm-up).
        """
        if self._tip is not None:
            return self._tip
        last = _GENESIS
        if self.path.exists():
            try:
                with self.path.open("r", encoding="utf-8") as fh:
                    for line in fh:
                        line = line.strip()
                        if not line:
                            continue
                        try:
                            last = json.loads(line).get("hash", last)
                        except json.JSONDecodeError:
                            continue
            except OSError:
                last = _GENESIS
        self._tip = last
        return last

    def write(self, event: str, **fields: Any) -> None:
        record = {
            "ts": datetime.now(UTC).isoformat(),
            "event": event,
            **fields,
        }
        record["prev"] = self._last_hash()
        record["hash"] = _record_hash(record, record["prev"])
        with self.path.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(record, default=str) + "\n")
        self._tip = record["hash"]        # advance the cached tip


@dataclass
class ChainResult:
    ok: bool
    records: int
    broken_at: int | None = None      # 1-based line number of the first bad link
    detail: str = ""


def verify_chain(path: Path) -> ChainResult:
    """Verify the hash chain of an audit log. Detects any post-hoc edit/delete."""
    if not path.exists():
        return ChainResult(ok=True, records=0, detail="no audit log yet")
    prev = _GENESIS
    n = 0
    try:
        with path.open("r", encoding="utf-8") as fh:
            for i, line in enumerate(fh, 1):
                line = line.strip()
                if not line:
                    continue
                try:
                    rec = json.loads(line)
                except json.JSONDecodeError:
                    return ChainResult(False, n, i, f"line {i}: not valid JSON")
                if rec.get("prev") != prev:
                    return ChainResult(False, n, i,
                                       f"line {i}: prev-hash does not match the chain")
                if _record_hash(rec, prev) != rec.get("hash"):
                    return ChainResult(False, n, i,
                                       f"line {i}: content hash mismatch (record edited)")
                prev = rec["hash"]
                n += 1
    except OSError as exc:
        return ChainResult(False, n, None, str(exc))
    return ChainResult(ok=True, records=n, detail=f"{n} records, chain intact")
