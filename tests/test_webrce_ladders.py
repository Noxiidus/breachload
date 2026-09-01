"""Generalized web-attack ladders: LFI -> RCE, upload-bypass."""

from breachload.analysis.webrce_ladders import (
    UPLOAD_EXTENSION_LADDER,
    lfi_to_rce_ladder,
    upload_bypass_requests,
)


class TestLfiLadder:
    def test_covers_the_class(self):
        rungs = lfi_to_rce_ladder("http://x/index.php?f=x", "f")
        techs = [t for t, _c in rungs]
        # /etc/passwd sanity, PHP wrappers, log/env poison, session
        assert any("/etc/passwd" in t for t in techs)
        assert any("wrapper" in t for t in techs)
        assert any("Log poison" in t for t in techs)
        assert any("environ" in t for t in techs)

    def test_uses_correct_param(self):
        rungs = lfi_to_rce_ladder("http://x/?page=x", "page")
        cmd0 = rungs[0][1]
        assert "?page=/etc/passwd" in cmd0

    def test_url_host_extracted(self):
        rungs = lfi_to_rce_ladder("http://target.htb/vuln?f=x", "f")
        ssh_step = next(c for _t, c in rungs if c.startswith("ssh "))
        assert "@target.htb" in ssh_step


class TestUploadLadder:
    def test_extension_ladder_wide(self):
        assert any(n.endswith(".phtml") for n in UPLOAD_EXTENSION_LADDER)
        assert any(n.endswith(".phar") for n in UPLOAD_EXTENSION_LADDER)
        assert any("%00" in n for n in UPLOAD_EXTENSION_LADDER)
        assert any(".aspx" in n for n in UPLOAD_EXTENSION_LADDER)

    def test_curl_argv_shape(self):
        reqs = upload_bypass_requests("http://x/upload")
        # every rung is a plain-argv curl POST to the upload URL
        for _t, argv in reqs:
            assert argv[0] == "curl" and "http://x/upload" == argv[-1]

    def test_custom_field(self):
        reqs = upload_bypass_requests("http://x/u", field="avatar")
        assert any("avatar=@-" in " ".join(a) for _t, a in reqs)
