"""NVD feed import.

Converts an NVD 2.0 feed (the `vulnerabilities[].cve` shape returned by the NVD
API or its JSON dumps) into breachload's compact KB schema
({match, range, cve, severity, name}), so the small curated knowledge base can be
grown from an authoritative source. Offline: it parses JSON you already have.
"""

from __future__ import annotations

_SEVERITY_MAP = {
    "CRITICAL": "critical", "HIGH": "high", "MEDIUM": "medium",
    "LOW": "low", "NONE": "info",
}


def parse_nvd(data: dict) -> list[dict]:
    """Return KB entries for every CVE in an NVD 2.0 `data` dict that has a
    usable product + version range. CVEs without a version-bounded CPE match are
    skipped (they can't be matched against a service banner)."""
    out: list[dict] = []
    for item in data.get("vulnerabilities", []):
        cve = item.get("cve", {})
        entry = _entry_for(cve)
        if entry is not None:
            out.append(entry)
    return out


def _entry_for(cve: dict) -> dict | None:
    cve_id = cve.get("id")
    if not cve_id:
        return None
    match = _first_versioned_cpe(cve)
    if match is None:
        return None
    product, version_range = match
    return {
        "match": [product],
        "range": version_range,
        "cve": cve_id,
        "severity": _severity(cve),
        "name": _name(cve, cve_id),
    }


def _first_versioned_cpe(cve: dict) -> tuple[str, str] | None:
    for config in cve.get("configurations", []):
        for node in config.get("nodes", []):
            for cpe in node.get("cpeMatch", []):
                bounds = _range_from_cpe(cpe)
                if bounds is None:
                    continue
                product = _product_from_criteria(cpe.get("criteria", ""))
                if product:
                    return product, bounds
    return None


def _range_from_cpe(cpe: dict) -> str | None:
    parts = []
    if v := cpe.get("versionStartIncluding"):
        parts.append(f">={v}")
    if v := cpe.get("versionStartExcluding"):
        parts.append(f">{v}")
    if v := cpe.get("versionEndIncluding"):
        parts.append(f"<={v}")
    if v := cpe.get("versionEndExcluding"):
        parts.append(f"<{v}")
    return ",".join(parts) if parts else None


def _product_from_criteria(criteria: str) -> str:
    # cpe:2.3:a:vendor:product:version:...  -> field index 4 is the product.
    fields = criteria.split(":")
    if len(fields) > 4 and fields[4] not in ("", "*", "-"):
        return fields[4].replace("_", " ")
    return ""


def _severity(cve: dict) -> str:
    metrics = cve.get("metrics", {})
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        for metric in metrics.get(key, []):
            sev = metric.get("cvssData", {}).get("baseSeverity") or metric.get("baseSeverity")
            if sev:
                return _SEVERITY_MAP.get(sev.upper(), "medium")
    return "medium"


def _name(cve: dict, cve_id: str) -> str:
    for desc in cve.get("descriptions", []):
        if desc.get("lang") == "en":
            text = " ".join(desc.get("value", "").split())
            # ASCII "..." on purpose: names flow to a cp1250 Windows console that
            # can't encode a Unicode ellipsis.
            return (text[:90] + "...") if len(text) > 90 else text or cve_id
    return cve_id
