"""Hash identification, crack-command generation, and the live-run path."""

from breachload.analysis.hashcrack import (
    crack_commands,
    identify,
    run_hashcat,
)


class TestIdentify:
    def test_bcrypt(self):
        h = "$2b$12$" + "a" * 53
        assert identify(h)[0].name == "bcrypt"
        assert identify(h)[0].hashcat_mode == "3200"

    def test_sha512crypt(self):
        assert identify("$6$salt$" + "x" * 40)[0].name == "sha512crypt"

    def test_md5_and_ntlm_both_for_32hex(self):
        names = [t.name for t in identify("d41d8cd98f00b204e9800998ecf8427e")]
        assert "MD5" in names and "NTLM" in names

    def test_sha256_by_length(self):
        assert identify("a" * 64)[0].name == "SHA256"

    def test_netntlmv2(self):
        h = "user::DOMAIN:1122334455667788:" + "a" * 32 + ":0101000000000000"
        assert identify(h)[0].name == "NetNTLMv2"

    def test_krb5tgs(self):
        assert "Kerberos" in identify("$krb5tgs$23$*user$DOMAIN*$abcd")[0].name

    def test_phpass_wordpress(self):
        assert "phpass" in identify("$P$B" + "a" * 30)[0].name

    def test_unrecognized(self):
        assert identify("hello world") == []
        assert identify("") == []


class TestCrackCommands:
    def test_bcrypt_commands(self):
        cmds = crack_commands("$2b$12$" + "a" * 53)
        assert any("hashcat -m 3200" in c for c in cmds)
        assert any("john --format=bcrypt" in c for c in cmds)

    def test_none_for_unknown(self):
        assert crack_commands("not-a-hash") == []


class TestRunHashcat:
    def test_cracked_via_injected_runner(self):
        h = "5f4dcc3b5aa765d61d8327deb882cf99"   # md5("password")

        def fake(argv):
            return 0, f"{h}:password\n"

        res = run_hashcat(h, runner=fake)
        assert res.cracked and res.plaintext == "password" and res.ran

    def test_no_crack(self):
        h = "5f4dcc3b5aa765d61d8327deb882cf99"
        res = run_hashcat(h, runner=lambda argv: (1, ""))
        assert not res.cracked and res.ran

    def test_unknown_hash_not_run(self):
        res = run_hashcat("nope", runner=lambda argv: (0, ""))
        assert not res.cracked and not res.ran
