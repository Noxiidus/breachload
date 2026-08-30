"""Pivoting / tunnelling planner."""

from breachload.analysis.pivot import pivot_plan, render_pivot


class TestPivotPlan:
    def test_generates_all_methods(self):
        opts = pivot_plan("10.10.14.5", via_host="10.129.1.10",
                          subnet="172.16.5.0/24", ssh_user="bob")
        tools = {o.tool for o in opts}
        assert any("sshuttle" in t for t in tools)
        assert any("chisel" in t for t in tools)
        assert any("ligolo" in t for t in tools)
        assert any("-D" in t for t in tools)

    def test_lhost_filled_into_reverse_tunnels(self):
        opts = pivot_plan("10.10.14.5", via_host="1.2.3.4", subnet="172.16.5.0/24")
        chisel = next(o for o in opts if "chisel" in o.tool)
        assert any("10.10.14.5:" in c for c in chisel.target_cmds)

    def test_ssh_user_filled(self):
        opts = pivot_plan("10.10.14.5", via_host="1.2.3.4", ssh_user="alice")
        sshuttle = next(o for o in opts if "sshuttle" in o.tool)
        assert any("alice@1.2.3.4" in c for c in sshuttle.attacker_cmds)

    def test_placeholder_user_without_creds(self):
        opts = pivot_plan("10.10.14.5", via_host="1.2.3.4")
        sshuttle = next(o for o in opts if "sshuttle" in o.tool)
        assert any("<user>@1.2.3.4" in c for c in sshuttle.attacker_cmds)

    def test_subnet_used(self):
        opts = pivot_plan("L", via_host="H", subnet="192.168.50.0/24")
        assert any("192.168.50.0/24" in c
                   for o in opts for c in o.attacker_cmds + o.target_cmds)

    def test_default_lhost(self):
        opts = pivot_plan("", via_host="H", subnet="10.0.0.0/24")
        chisel = next(o for o in opts if "chisel" in o.tool)
        assert any("LHOST:" in c for c in chisel.target_cmds)


class TestRender:
    def test_render_has_attacker_and_target(self):
        lines = render_pivot(pivot_plan("L", via_host="H", subnet="10.0.0.0/24"))
        text = "\n".join(lines)
        assert "attacker$" in text and "target$" in text

    def test_render_empty(self):
        assert "no options" in render_pivot([])[0]
